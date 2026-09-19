<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Authentication;

use DateInterval;
use Heidi\Core\Application\Authentication\AuthenticationFailedException;
use Heidi\Core\Application\Authentication\PasswordAuthenticator;
use Heidi\Core\Application\Authentication\SessionOpener;
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
        $this->authenticator = new PasswordAuthenticator($this->users, $this->credentials, new NativePasswordHasher(), new SessionOpener($this->sessions, $this->clock, $this->events, new DateInterval('PT8H')), $this->clock, $this->events);
    }

    #[Test]
    public function aRightPasswordOpensASessionOfTheUser(): void
    {
        // Given
        $context = Fixtures::context($this->clock->now());

        // When
        $session = $this->authenticator->authenticate($this->tenant, ' alice ', 'correct horse', $context);

        // Then
        static::assertSame($this->alice, $session->user);
        static::assertSame(['pwd'], $session->methodReferences());
        static::assertSame('1', $session->authenticationContextClass()->value);
        static::assertSame($context, $session->createdFrom);
        static::assertEquals($this->clock->now(), $session->establishedAt);
        static::assertEquals($this->clock->now(), $session->authenticatedAt());
        static::assertSame([
            'pwd' => $this->clock->now()
                ->getTimestamp(),
        ], $session->proofs->toTimestamps());
        static::assertEquals($this->clock->now()->modify('+8 hours'), $session->expiresAt);
    }

    #[Test]
    public function aRightPasswordSavesTheSession(): void
    {
        // When
        $session = $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));

        // Then
        static::assertSame($session, $this->sessions->find($session->id));
    }

    #[Test]
    public function aRightPasswordDatesTheUseOfTheCredential(): void
    {
        // When
        $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));

        // Then
        static::assertEquals($this->clock->now(), $this->credentials->findByUser($this->alice, PasswordCredential::class)[0]->lastUsedAt);
    }

    #[Test]
    public function aRightPasswordAnnouncesTheAuthenticationOnce(): void
    {
        // When
        $session = $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));

        // Then
        static::assertCount(1, $this->events->events);
        static::assertSame($session, $this->events->of(UserAuthenticated::class)[0]->session);
    }

    #[Test]
    public function aWrongPasswordFails(): void
    {
        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'alice', 'wrong', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
            static::assertSame('Authentication failed.', $exception->getMessage());
        }
    }

    #[Test]
    public function aWrongPasswordIsRecordedWithTheUser(): void
    {
        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'alice', 'wrong', Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertCount(1, $this->events->events);
        $failure = $this->events->of(AuthenticationFailed::class)[0];
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $failure->reason);
        static::assertSame($this->alice, $failure->user);
        static::assertSame('alice', $failure->identifier);
        static::assertSame($this->tenant, $failure->tenant);
        static::assertEquals($this->clock->now(), $failure->occurredAt);
    }

    #[Test]
    public function aWrongPasswordOpensNoSession(): void
    {
        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'alice', 'wrong', Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertSame([], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
    }

    #[Test]
    public function anUnknownUserFails(): void
    {
        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'mallory', 'whatever', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::UnknownUser, $exception->reason);
        }
    }

    #[Test]
    public function anUnknownUserIsRecordedWithWhatWasTyped(): void
    {
        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'mallory', 'whatever', Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        $failure = $this->events->of(AuthenticationFailed::class)[0];
        static::assertSame(AuthenticationFailureReason::UnknownUser, $failure->reason);
        static::assertNull($failure->user);
        static::assertSame('mallory', $failure->identifier);
    }

    #[Test]
    public function aUserWithoutPasswordFails(): void
    {
        // Given
        $this->users->save(Fixtures::user($this->tenant, 'bob', 'bob-subject'));

        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'bob', 'anything', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::NoSuchCredential, $exception->reason);
        }
    }

    #[Test]
    public function aUserWithoutPasswordIsRecordedAsTheUser(): void
    {
        // Given
        $bob = Fixtures::user($this->tenant, 'bob', 'bob-subject');
        $this->users->save($bob);

        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'bob', 'anything', Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        $failure = $this->events->of(AuthenticationFailed::class)[0];
        static::assertSame(AuthenticationFailureReason::NoSuchCredential, $failure->reason);
        static::assertSame($bob, $failure->user);
    }

    /**
     * The account state is checked after the password: whoever does not know the password cannot tell a
     * disabled account from a wrong password.
     */
    #[Test]
    public function aDisabledUserWithAWrongPasswordFailsLikeAnyWrongPassword(): void
    {
        // Given
        $this->alice->disable(Fixtures::now());

        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'alice', 'wrong', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
        }
    }

    #[Test]
    public function aDisabledUserWithTheRightPasswordFailsAsDisabled(): void
    {
        // Given
        $this->alice->disable(Fixtures::now());

        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::DisabledUser, $exception->reason);
        }
    }

    #[Test]
    public function aUserOfAnotherTenantIsUnknownHere(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');

        // When
        try {
            $this->authenticator->authenticate($other, 'alice', 'correct horse', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::UnknownUser, $exception->reason);
        }
    }

    #[Test]
    public function aFailureIsRecordedInTheTenantItWasAttemptedIn(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');

        // When
        try {
            $this->authenticator->authenticate($other, 'alice', 'correct horse', Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertSame($other, $this->events->of(AuthenticationFailed::class)[0]->tenant);
    }

    #[Test]
    public function aLegacyHashIsReplacedAfterASuccessfulLogin(): void
    {
        // Given
        $carol = Fixtures::user($this->tenant, 'carol', 'carol-subject');
        $this->users->save($carol);
        $this->credentials->save(new PasswordCredential(Uuid::v7(), $carol, new PasswordHash(PasswordAlgorithm::Bcrypt, password_hash('carol pass', PASSWORD_BCRYPT)), Fixtures::now()));

        // When
        $this->authenticator->authenticate($this->tenant, 'carol', 'carol pass', Fixtures::context());

        // Then
        $credential = $this->credentials->findByUser($carol, PasswordCredential::class)[0];
        static::assertSame(PasswordAlgorithm::Argon2id, $credential?->hash->algorithm);
        static::assertEquals($this->clock->now(), $credential->hashChangedAt);
        static::assertTrue(new NativePasswordHasher()->verify($credential->hash, 'carol pass'));
    }

    #[Test]
    public function aRehashIsAnnounced(): void
    {
        // Given
        $carol = Fixtures::user($this->tenant, 'carol', 'carol-subject');
        $this->users->save($carol);
        $this->credentials->save(new PasswordCredential(Uuid::v7(), $carol, new PasswordHash(PasswordAlgorithm::Bcrypt, password_hash('carol pass', PASSWORD_BCRYPT)), Fixtures::now()));

        // When
        $this->authenticator->authenticate($this->tenant, 'carol', 'carol pass', Fixtures::context());

        // Then
        static::assertCount(1, $this->events->of(PasswordRehashed::class));
        static::assertSame($this->credentials->findByUser($carol, PasswordCredential::class)[0], $this->events->of(PasswordRehashed::class)[0]->credential);
    }
}
