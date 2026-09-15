<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Authentication;

use function count;
use DateInterval;
use Heidi\Core\Application\Authentication\AuthenticationFailedException;
use Heidi\Core\Application\Authentication\PasswordAuthenticator;
use Heidi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Heidi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Heidi\Core\Bridge\InMemory\InMemoryUserRepository;
use Heidi\Core\Bridge\Password\NativePasswordHasher;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Credential\PasswordCredential;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Domain\Event\AuthenticationFailed;
use Heidi\Core\Domain\Event\AuthenticationFailureReason;
use Heidi\Core\Domain\Event\PasswordRehashed;
use Heidi\Core\Domain\Event\UserAuthenticated;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use const PASSWORD_BCRYPT;
use function password_hash;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

final class PasswordAuthenticatorTest extends TestCase
{
    private Tenant $tenant;

    private User $alice;

    private InMemoryUserRepository $users;

    private InMemoryCredentialRepository $credentials;

    private InMemoryAuthenticationSessionRepository $sessions;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private PasswordAuthenticator $authenticator;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->users = new InMemoryUserRepository();
        $this->users->save($this->alice);
        $this->credentials = new InMemoryCredentialRepository();
        $this->credentials->save(new PasswordCredential(Uuid::v7(), $this->alice, new NativePasswordHasher()->hash('correct horse'), Fixtures::now()));
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-15T12:00:00+00:00');
        $this->authenticator = new PasswordAuthenticator($this->users, $this->credentials, new NativePasswordHasher(), $this->sessions, $this->clock, $this->events, new DateInterval('PT8H'));
    }

    #[Test]
    public function aRightPasswordOpensASessionAndAnnouncesIt(): void
    {
        $context = Fixtures::context($this->clock->now());

        $session = $this->authenticator->authenticate($this->tenant, ' alice ', 'correct horse', $context, 'urn:acme:pwd');

        static::assertSame($this->alice, $session->user);
        static::assertSame(['pwd'], $session->methodReferences());
        static::assertSame('urn:acme:pwd', $session->authenticationContextClass);
        static::assertSame($context, $session->createdFrom);
        static::assertEquals($this->clock->now(), $session->establishedAt);
        static::assertEquals($this->clock->now(), $session->authenticatedAt());
        static::assertSame([
            'pwd' => $this->clock->now()
                ->getTimestamp(),
        ], $session->proofs->toTimestamps());
        static::assertEquals($this->clock->now()->modify('+8 hours'), $session->expiresAt);
        static::assertSame($session, $this->sessions->find($session->id));
        static::assertEquals($this->clock->now(), $this->credentials->findPasswordCredential($this->alice)?->lastUsedAt);

        static::assertCount(1, $this->events->events);
        static::assertSame($session, $this->events->of(UserAuthenticated::class)[0]->session);
    }

    #[Test]
    public function aWrongPasswordFailsAndIsRecordedWithTheUser(): void
    {
        $this->expectFailure(AuthenticationFailureReason::InvalidCredential, 'alice', 'wrong');

        $failure = $this->events->of(AuthenticationFailed::class)[0];
        static::assertSame($this->alice, $failure->user);
        static::assertSame('alice', $failure->identifier);
        static::assertSame([], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
    }

    #[Test]
    public function anUnknownUserFailsAndIsRecordedWithWhatWasTyped(): void
    {
        $this->expectFailure(AuthenticationFailureReason::UnknownUser, 'mallory', 'whatever');

        $failure = $this->events->of(AuthenticationFailed::class)[0];
        static::assertNull($failure->user);
        static::assertSame('mallory', $failure->identifier);
    }

    #[Test]
    public function aUserWithoutPasswordFails(): void
    {
        $bob = Fixtures::user($this->tenant, 'bob', 'bob-subject');
        $this->users->save($bob);

        $this->expectFailure(AuthenticationFailureReason::NoSuchCredential, 'bob', 'anything');
        static::assertSame($bob, $this->events->of(AuthenticationFailed::class)[0]->user);
    }

    /**
     * The account state is checked after the password: whoever does not know the password cannot tell a
     * disabled account from a wrong password.
     */
    #[Test]
    public function aDisabledUserFailsOnlyWithTheRightPassword(): void
    {
        $this->alice->disable(Fixtures::now());

        $this->expectFailure(AuthenticationFailureReason::InvalidCredential, 'alice', 'wrong');
        $this->expectFailure(AuthenticationFailureReason::DisabledUser, 'alice', 'correct horse');
    }

    #[Test]
    public function aUserOfAnotherTenantIsUnknownHere(): void
    {
        $this->expectFailure(AuthenticationFailureReason::UnknownUser, 'alice', 'correct horse', Fixtures::tenant('other', 'https://id.other.example'));
    }

    #[Test]
    public function aLegacyHashIsReplacedAfterASuccessfulLogin(): void
    {
        $carol = Fixtures::user($this->tenant, 'carol', 'carol-subject');
        $this->users->save($carol);
        $this->credentials->save(new PasswordCredential(Uuid::v7(), $carol, new PasswordHash(PasswordAlgorithm::Bcrypt, password_hash('carol pass', PASSWORD_BCRYPT)), Fixtures::now()));

        $this->authenticator->authenticate($this->tenant, 'carol', 'carol pass', Fixtures::context());

        $credential = $this->credentials->findPasswordCredential($carol);
        static::assertSame(PasswordAlgorithm::Argon2id, $credential?->hash->algorithm);
        static::assertEquals($this->clock->now(), $credential->hashChangedAt);
        static::assertCount(1, $this->events->of(PasswordRehashed::class));
        static::assertSame($credential, $this->events->of(PasswordRehashed::class)[0]->credential);
        static::assertTrue(new NativePasswordHasher()->verify($credential->hash, 'carol pass'));
    }

    #[Test]
    public function theDefaultSessionLifetimeIsTwelveHours(): void
    {
        $authenticator = new PasswordAuthenticator($this->users, $this->credentials, new NativePasswordHasher(), $this->sessions, $this->clock, $this->events);

        $session = $authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context());

        static::assertEquals($this->clock->now()->modify('+12 hours'), $session->expiresAt);
    }

    private function expectFailure(AuthenticationFailureReason $reason, string $identifier, string $password, ?Tenant $tenant = null): void
    {
        $before = count($this->events->events);
        try {
            $this->authenticator->authenticate($tenant ?? $this->tenant, $identifier, $password, Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            static::assertSame($reason, $exception->reason);
            static::assertSame('Authentication failed.', $exception->getMessage());
        }
        $failures = $this->events->of(AuthenticationFailed::class);
        static::assertCount($before + 1, $this->events->events);
        $failure = $failures[count($failures) - 1];
        static::assertSame($reason, $failure->reason);
        static::assertEquals($this->clock->now(), $failure->occurredAt);
        static::assertSame($tenant ?? $this->tenant, $failure->tenant);
    }
}
