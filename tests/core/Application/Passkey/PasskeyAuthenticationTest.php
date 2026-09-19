<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Passkey;

use DateInterval;
use Heidi\Core\Application\Authentication\AuthenticationFailedException;
use Heidi\Core\Application\Passkey\PasskeyAuthentication;
use Heidi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Heidi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Heidi\Core\Domain\Credential\PasskeyCredential;
use Heidi\Core\Domain\Event\AuthenticationFailed;
use Heidi\Core\Domain\Event\AuthenticationFailureReason;
use Heidi\Core\Domain\Event\PasskeyUsed;
use Heidi\Core\Domain\Event\UserAuthenticated;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasskeyAuthenticator;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * Architecture §3.2, §3.4: a session opened on what an assertion proved, WebAuthn Level 3 §7.2.
 */
final class PasskeyAuthenticationTest extends TestCase
{
    private Tenant $tenant;

    private User $alice;

    private PasskeyCredential $passkey;

    private InMemoryCredentialRepository $credentials;

    private InMemoryAuthenticationSessionRepository $sessions;

    private FakePasskeyAuthenticator $ceremony;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private PasskeyAuthentication $authentication;

    private PublicKeyCredentialRequestOptions $options;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->passkey = Fixtures::passkey($this->alice, credentialId: 'alice-key');
        $this->credentials = new InMemoryCredentialRepository();
        $this->credentials->save($this->passkey);
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->ceremony = new FakePasskeyAuthenticator();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-19T12:00:00+00:00');
        $this->authentication = new PasskeyAuthentication($this->credentials, $this->ceremony, $this->sessions, $this->clock, $this->events, new DateInterval('PT8H'));
        $this->options = $this->authentication->requestOptions($this->tenant);
    }

    #[Test]
    public function aDiscoverableCredentialIsAskedForWithoutAnAllowList(): void
    {
        // When
        $options = $this->authentication->requestOptions($this->tenant);

        // Then
        static::assertSame([], $options->allowCredentials);
    }

    #[Test]
    public function aUserWhoNamedThemselfIsAskedForTheirActivePasskeys(): void
    {
        // Given
        $revoked = Fixtures::passkey($this->alice, credentialId: 'old-key');
        $revoked->revoke(Fixtures::now());
        $this->credentials->save($revoked);

        // When
        $options = $this->authentication->requestOptions($this->tenant, $this->alice);

        // Then
        static::assertCount(1, $options->allowCredentials);
        static::assertSame('alice-key', $options->allowCredentials[0]->id);
    }

    #[Test]
    public function aVerifiedAssertionOpensASessionOnWhatItProved(): void
    {
        // Given
        $this->ceremony->verifies($this->passkey, Fixtures::authenticatorData(userPresent: true, userVerified: true, signCount: 1));
        $context = Fixtures::context($this->clock->now());

        // When
        $session = $this->authentication->authenticate($this->tenant, $this->options, '{}', $context);

        // Then
        static::assertSame($this->alice, $session->user);
        static::assertSame(['hwk', 'user', 'mfa'], $session->methodReferences());
        static::assertSame('phrh', $session->authenticationContextClass()->value);
        static::assertSame($context, $session->createdFrom);
        static::assertEquals($this->clock->now(), $session->authenticatedAt());
        static::assertEquals($this->clock->now()->modify('+8 hours'), $session->expiresAt);
        static::assertSame($session, $this->sessions->find($session->id));
    }

    #[Test]
    public function aVerifiedAssertionRecordsTheUseOfThePasskey(): void
    {
        // Given
        $this->ceremony->verifies($this->passkey, Fixtures::authenticatorData(signCount: 3));

        // When
        $this->authentication->authenticate($this->tenant, $this->options, '{}', Fixtures::context($this->clock->now()));

        // Then
        static::assertSame(3, $this->passkey->signCount);
        static::assertEquals($this->clock->now(), $this->passkey->lastUsedAt);
    }

    #[Test]
    public function aVerifiedAssertionAnnouncesTheUseThenTheAuthentication(): void
    {
        // Given
        $this->ceremony->verifies($this->passkey, Fixtures::authenticatorData(signCount: 3));
        $context = Fixtures::context($this->clock->now());

        // When
        $session = $this->authentication->authenticate($this->tenant, $this->options, '{}', $context);

        // Then
        static::assertCount(2, $this->events->events);
        $used = $this->events->of(PasskeyUsed::class)[0];
        static::assertSame($this->passkey, $used->credential);
        static::assertSame($context, $used->context);
        static::assertFalse($used->signCountRegressed);
        static::assertSame($session, $this->events->of(UserAuthenticated::class)[0]->session);
    }

    /**
     * WebAuthn Level 3 §6.1.1: a count that did not grow is told, never refused, a synced passkey keeps it at zero.
     */
    #[Test]
    public function aSignCountThatDidNotGrowIsToldNotRefused(): void
    {
        // Given
        $this->passkey->recordUse(Fixtures::authenticatorData(signCount: 5), Fixtures::now());
        $this->ceremony->verifies($this->passkey, Fixtures::authenticatorData(signCount: 5));

        // When
        $session = $this->authentication->authenticate($this->tenant, $this->options, '{}', Fixtures::context($this->clock->now()));

        // Then
        static::assertSame($this->alice, $session->user);
        static::assertTrue($this->events->of(PasskeyUsed::class)[0]->signCountRegressed);
    }

    #[Test]
    public function aRefusedCeremonyFailsAndIsRecordedWithoutAUser(): void
    {
        // Given
        $this->ceremony->refuses('The signature is invalid.');
        $context = Fixtures::context($this->clock->now());

        // When
        try {
            $this->authentication->authenticate($this->tenant, $this->options, '{}', $context);
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
            $failed = $this->events->of(AuthenticationFailed::class)[0];
            static::assertNull($failed->method);
            static::assertNull($failed->identifier);
            static::assertNull($failed->user);
            static::assertSame($context, $failed->context);
            static::assertSame([], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
        }
    }

    #[Test]
    public function aRevokedPasskeyIsRefusedAndRecordedWithItsUser(): void
    {
        // Given
        $this->passkey->revoke(Fixtures::now());
        $this->ceremony->verifies($this->passkey, Fixtures::authenticatorData(backupEligible: true));

        // When
        try {
            $this->authentication->authenticate($this->tenant, $this->options, '{}', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::RevokedCredential, $exception->reason);
            $failed = $this->events->of(AuthenticationFailed::class)[0];
            static::assertSame('swk', $failed->method?->value);
            static::assertSame($this->alice, $failed->user);
            static::assertNull($this->passkey->lastUsedAt);
        }
    }

    #[Test]
    public function aDisabledUserIsRefused(): void
    {
        // Given
        $this->alice->disable(Fixtures::now());
        $this->ceremony->verifies($this->passkey, Fixtures::authenticatorData());

        // When
        try {
            $this->authentication->authenticate($this->tenant, $this->options, '{}', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::DisabledUser, $exception->reason);
            static::assertSame($this->alice, $this->events->of(AuthenticationFailed::class)[0]->user);
        }
    }

    #[Test]
    public function aPasskeyOfAnotherTenantIsRefused(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $this->ceremony->verifies(Fixtures::passkey(Fixtures::user($other)), Fixtures::authenticatorData());

        // When
        try {
            $this->authentication->authenticate($this->tenant, $this->options, '{}', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
            static::assertNull($this->events->of(AuthenticationFailed::class)[0]->user);
        }
    }
}
