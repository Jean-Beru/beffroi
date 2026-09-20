<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Authentication;

use DateInterval;
use Heidi\Core\Application\Authentication\AuthenticationFailedException;
use Heidi\Core\Application\Authentication\LoginCompletion;
use Heidi\Core\Application\Authentication\SessionOpener;
use Heidi\Core\Application\Totp\ActiveTotp;
use Heidi\Core\Application\Totp\TotpAuthentication;
use Heidi\Core\Application\Totp\TotpCodeMatcher;
use Heidi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Heidi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Heidi\Core\Bridge\InMemory\InMemoryUserRepository;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Credential\PasswordCredential;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Domain\Event\AuthenticationFailed;
use Heidi\Core\Domain\Event\AuthenticationFailureReason;
use Heidi\Core\Domain\Event\TotpUsed;
use Heidi\Core\Domain\Event\UserAuthenticated;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\PendingLogin;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakeAttemptLimiter;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Core\Tests\Fixture\Totps;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.2: the login the password held is completed by a code, and the session is opened on
 * both methods at once, dated when the login ended.
 */
final class LoginCompletionTest extends TestCase
{
    private Tenant $tenant;

    private User $alice;

    private InMemoryAuthenticationSessionRepository $sessions;

    private RecordingEventDispatcher $events;

    private FakeAttemptLimiter $attempts;

    private MockClock $clock;

    private PendingLogin $login;

    private LoginCompletion $completion;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $users = new InMemoryUserRepository();
        $users->save($this->alice);
        $hasher = new FakePasswordHasher();
        $credentials = new InMemoryCredentialRepository();
        $credentials->save(new PasswordCredential(Uuid::v7(), $this->alice, new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$alice'), Fixtures::now()));
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->events = new RecordingEventDispatcher();
        $this->attempts = new FakeAttemptLimiter(5);
        $this->clock = new MockClock('2026-09-20T12:00:15+00:00');
        // enrolled an hour ago: the step of its first code is long past
        $credentials->save(Totps::credential($this->alice, $hasher, Totps::stepAt($this->clock->now()->modify('-1 hour')), createdAt: $this->clock->now()->modify('-1 hour')));
        // the password was typed a minute ago
        $this->login = PendingLogin::provenAt($this->alice->id, [AuthenticationMethod::password()], $this->clock->now()->modify('-1 minute'));
        $this->completion = new LoginCompletion(
            $users,
            new TotpAuthentication($credentials, new ActiveTotp($credentials), new TotpCodeMatcher(Totps::algorithm()), Totps::sealer(), $hasher, $this->attempts, $this->clock, $this->events),
            new SessionOpener($this->sessions, $this->clock, $this->events, new DateInterval('PT8H')),
            $this->clock,
            $this->events,
        );
    }

    #[Test]
    public function aRightCodeOpensASessionOnWhatBothStepsProved(): void
    {
        // Given
        $context = Fixtures::context($this->clock->now());

        // When
        $session = $this->completion->complete($this->tenant, $this->login, Totps::codeAt($this->clock->now()), $context);

        // Then
        static::assertSame($this->alice, $session->user);
        static::assertSame(['pwd', 'otp', 'mfa'], $session->methodReferences());
        static::assertSame('2', $session->authenticationContextClass()->value);
        static::assertSame($context, $session->createdFrom);
        static::assertEquals($this->clock->now()->modify('+8 hours'), $session->expiresAt);
    }

    /**
     * The authentication took place when the code passed, in the sense of auth_time: the password of the
     * first step is dated then too, not a minute earlier.
     */
    #[Test]
    public function bothMethodsAreDatedWhenTheLoginEnds(): void
    {
        // When
        $session = $this->completion->complete($this->tenant, $this->login, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));

        // Then
        $now = $this->clock->now()
            ->getTimestamp();
        static::assertSame([
            'pwd' => $now,
            'otp' => $now,
        ], $session->proofs->toTimestamps());
        static::assertEquals($this->clock->now(), $session->authenticatedAt());
    }

    /**
     * The first step may have proven more than one method (a PIN and a smart card, say): all of them are
     * carried onto the session, not the first one.
     */
    #[Test]
    public function everythingTheFirstStepProvedIsCarriedOntoTheSession(): void
    {
        // Given
        $login = PendingLogin::provenAt($this->alice->id, [new AuthenticationMethod(AuthenticationMethod::PIN), new AuthenticationMethod(AuthenticationMethod::SMART_CARD)], $this->clock->now()->modify('-1 minute'));

        // When
        $session = $this->completion->complete($this->tenant, $login, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame(['pin', 'sc', 'otp', 'mfa'], $session->methodReferences());
    }

    #[Test]
    public function aRightCodeSavesTheSession(): void
    {
        // When
        $session = $this->completion->complete($this->tenant, $this->login, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame($session, $this->sessions->find($session->id));
    }

    #[Test]
    public function aRightCodeAnnouncesTheCodeThenTheAuthentication(): void
    {
        // When
        $session = $this->completion->complete($this->tenant, $this->login, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));

        // Then
        static::assertCount(2, $this->events->events);
        static::assertInstanceOf(TotpUsed::class, $this->events->events[0]);
        static::assertSame($session, $this->events->of(UserAuthenticated::class)[0]->session);
    }

    #[Test]
    public function aWrongCodeFails(): void
    {
        // When
        try {
            $this->completion->complete($this->tenant, $this->login, '000000', Fixtures::context($this->clock->now()));
            static::fail('The login should not have been completed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
        }
    }

    #[Test]
    public function aWrongCodeOpensNoSession(): void
    {
        // When
        try {
            $this->completion->complete($this->tenant, $this->login, '000000', Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertSame([], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
    }

    /**
     * Five minutes to type a code: past that, the first factor is proven again, and the code is not read.
     */
    #[Test]
    public function anExpiredLoginIsRefusedBeforeTheCodeIsRead(): void
    {
        // Given
        $login = PendingLogin::provenAt($this->alice->id, [AuthenticationMethod::password()], $this->clock->now()->modify('-5 minutes'));

        // When
        try {
            $this->completion->complete($this->tenant, $login, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));
            static::fail('The login should not have been completed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::ExpiredLogin, $exception->reason);
            static::assertSame([], $this->attempts->attempts);
            static::assertSame([], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
        }
    }

    #[Test]
    public function anExpiredLoginIsRecordedWithTheUser(): void
    {
        // Given
        $login = PendingLogin::provenAt($this->alice->id, [AuthenticationMethod::password()], $this->clock->now()->modify('-5 minutes'));
        $context = Fixtures::context($this->clock->now());

        // When
        try {
            $this->completion->complete($this->tenant, $login, Totps::codeAt($this->clock->now()), $context);
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertCount(1, $this->events->events);
        $failure = $this->events->of(AuthenticationFailed::class)[0];
        static::assertSame(AuthenticationFailureReason::ExpiredLogin, $failure->reason);
        static::assertSame('otp', $failure->method?->value);
        static::assertSame('alice', $failure->identifier);
        static::assertSame($this->alice, $failure->user);
        static::assertSame($this->tenant, $failure->tenant);
        static::assertSame($context, $failure->context);
    }

    #[Test]
    public function aLoginOfAUserWhoNoLongerExistsFails(): void
    {
        // Given
        $gone = Uuid::v7();
        $login = PendingLogin::provenAt($gone, [AuthenticationMethod::password()], $this->clock->now()->modify('-1 minute'));

        // When
        try {
            $this->completion->complete($this->tenant, $login, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));
            static::fail('The login should not have been completed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::UnknownUser, $exception->reason);
            $failure = $this->events->of(AuthenticationFailed::class)[0];
            static::assertNull($failure->user);
            static::assertSame($gone->toRfc4122(), $failure->identifier);
        }
    }

    #[Test]
    public function aLoginOfAUserOfAnotherTenantIsUnknownHere(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');

        // When
        try {
            $this->completion->complete($other, $this->login, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));
            static::fail('The login should not have been completed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::UnknownUser, $exception->reason);
            static::assertSame($other, $this->events->of(AuthenticationFailed::class)[0]->tenant);
        }
    }
}
