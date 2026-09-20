<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Totp;

use function array_filter;
use Heidi\Core\Application\Authentication\AuthenticationFailedException;
use Heidi\Core\Application\Totp\ActiveTotp;
use Heidi\Core\Application\Totp\TotpAuthentication;
use Heidi\Core\Application\Totp\TotpCodeMatcher;
use Heidi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Heidi\Core\Domain\Credential\BackupCode;
use Heidi\Core\Domain\Credential\TotpCredential;
use Heidi\Core\Domain\Event\AuthenticationFailed;
use Heidi\Core\Domain\Event\AuthenticationFailureReason;
use Heidi\Core\Domain\Event\TotpUsed;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Port\CredentialRepositoryInterface;
use Heidi\Core\Tests\Fixture\FakeAttemptLimiter;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Core\Tests\Fixture\Totps;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Architecture §3.4: a code verified for a user who named themself, accepted once within one step of
 * drift (RFC 6238 §5.2), or a backup code spent once; the attempts counted first.
 */
final class TotpAuthenticationTest extends TestCase
{
    private User $alice;

    private FakePasswordHasher $hasher;

    private FakeAttemptLimiter $attempts;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private TotpCredential $totp;

    private TotpAuthentication $authentication;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $credentials = new InMemoryCredentialRepository();
        $this->hasher = new FakePasswordHasher();
        $this->attempts = new FakeAttemptLimiter(5);
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-20T12:00:15+00:00');
        // enrolled an hour ago: the step of its first code is long past
        $this->totp = Totps::credential($this->alice, $this->hasher, Totps::stepAt($this->clock->now()->modify('-1 hour')), createdAt: $this->clock->now()->modify('-1 hour'));
        $credentials->save($this->totp);
        $this->authentication = new TotpAuthentication($credentials, new ActiveTotp($credentials), new TotpCodeMatcher(Totps::algorithm()), Totps::sealer(), $this->hasher, $this->attempts, $this->clock, $this->events);
    }

    #[Test]
    public function aValidCodeProvesAOneTimePassword(): void
    {
        // When
        $method = $this->authentication->authenticate($this->alice, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame('otp', $method->value);
    }

    #[Test]
    public function aValidCodeRecordsTheUse(): void
    {
        // When
        $this->authentication->authenticate($this->alice, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame(Totps::stepAt($this->clock->now()), $this->totp->lastAcceptedStep);
        static::assertEquals($this->clock->now(), $this->totp->lastUsedAt);
    }

    /**
     * The in-memory repository holds the very object, so a save is only seen through a mock.
     */
    #[Test]
    #[DataProvider('provideAcceptedCodes')]
    public function anAcceptedCodeSavesTheCredential(string $code): void
    {
        // Given
        $credentials = $this->createMock(CredentialRepositoryInterface::class);
        $credentials->method('findByUser')
            ->willReturn([$this->totp]);
        $credentials->expects(static::once())->method('save')->with($this->totp);
        $authentication = new TotpAuthentication($credentials, new ActiveTotp($credentials), new TotpCodeMatcher(Totps::algorithm()), Totps::sealer(), $this->hasher, $this->attempts, $this->clock, $this->events);

        // When
        $authentication->authenticate($this->alice, $code === 'totp' ? Totps::codeAt($this->clock->now()) : $code, Fixtures::context($this->clock->now()));

        // Then
        static::assertEquals($this->clock->now(), $this->totp->lastUsedAt);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAcceptedCodes(): iterable
    {
        yield 'a code of the authenticator' => ['totp'];
        yield 'a backup code' => [Totps::BACKUP_CODES[2]];
    }

    #[Test]
    public function aValidCodeIsAnnouncedAsACodeOfTheAuthenticator(): void
    {
        // Given
        $context = Fixtures::context($this->clock->now());

        // When
        $this->authentication->authenticate($this->alice, Totps::codeAt($this->clock->now()), $context);

        // Then
        static::assertCount(1, $this->events->events);
        $used = $this->events->of(TotpUsed::class)[0];
        static::assertSame($this->totp, $used->credential);
        static::assertSame($context, $used->context);
        static::assertEquals($this->clock->now(), $used->occurredAt);
        static::assertFalse($used->backupCode);
    }

    /**
     * RFC 6238 §5.2: the same code is not accepted twice.
     */
    #[Test]
    public function theSameCodeTwiceIsRefusedAsReplayed(): void
    {
        // Given
        $code = Totps::codeAt($this->clock->now());
        $this->authentication->authenticate($this->alice, $code, Fixtures::context($this->clock->now()));
        $this->clock->sleep(5);

        // When
        $exception = $this->failToAuthenticate($code);

        // Then
        static::assertSame(AuthenticationFailureReason::ReplayedCode, $exception->reason);
    }

    /**
     * RFC 6238 §5.2: the accepted step moves forward, never back; after the code of the next step, the
     * code of this one is refused although it is in the window.
     */
    #[Test]
    public function aCodeOfAnEarlierStepIsRefusedAfterALaterOne(): void
    {
        // Given
        $this->authentication->authenticate($this->alice, Totps::codeAt($this->clock->now()->modify('+30 seconds')), Fixtures::context($this->clock->now()));

        // When
        $exception = $this->failToAuthenticate(Totps::codeAt($this->clock->now()));

        // Then
        static::assertSame(AuthenticationFailureReason::ReplayedCode, $exception->reason);
    }

    /**
     * RFC 6238 §5.2: one step of clock drift on each side.
     */
    #[Test]
    #[DataProvider('provideDriftsInTheWindow')]
    public function aCodeOnePeriodAwayIsAccepted(string $drift): void
    {
        // When
        $method = $this->authentication->authenticate($this->alice, Totps::codeAt($this->clock->now()->modify($drift)), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame('otp', $method->value);
        static::assertSame(Totps::stepAt($this->clock->now()->modify($drift)), $this->totp->lastAcceptedStep);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDriftsInTheWindow(): iterable
    {
        yield 'one period early' => ['-30 seconds'];
        yield 'one period late' => ['+30 seconds'];
    }

    #[Test]
    #[DataProvider('provideDriftsOutOfTheWindow')]
    public function aCodeTwoPeriodsAwayIsRefused(string $drift): void
    {
        // When
        $exception = $this->failToAuthenticate(Totps::codeAt($this->clock->now()->modify($drift)));

        // Then
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
        static::assertNull($this->totp->lastUsedAt);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDriftsOutOfTheWindow(): iterable
    {
        yield 'two periods early' => ['-60 seconds'];
        yield 'two periods late' => ['+60 seconds'];
    }

    #[Test]
    public function aBackupCodeIsAcceptedOnceAndAnnouncedAsSuch(): void
    {
        // Given
        $context = Fixtures::context($this->clock->now());

        // When
        $method = $this->authentication->authenticate($this->alice, Totps::BACKUP_CODES[3], $context);

        // Then
        static::assertSame('otp', $method->value);
        static::assertTrue($this->totp->backupCodes[3]->isSpent());
        static::assertEquals($this->clock->now(), $this->totp->backupCodes[3]->usedAt);
        static::assertCount(9, array_filter($this->totp->backupCodes, static fn (BackupCode $code): bool => ! $code->isSpent()));
        static::assertEquals($this->clock->now(), $this->totp->lastUsedAt);
        $used = $this->events->of(TotpUsed::class)[0];
        static::assertTrue($used->backupCode);
        static::assertSame($context, $used->context);
    }

    #[Test]
    public function aBackupCodeSpentIsRefusedTheSecondTime(): void
    {
        // Given
        $this->authentication->authenticate($this->alice, Totps::BACKUP_CODES[3], Fixtures::context($this->clock->now()));

        // When
        $exception = $this->failToAuthenticate(Totps::BACKUP_CODES[3]);

        // Then
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
    }

    #[Test]
    public function aBackupCodeIsReadAsTheUserTypedIt(): void
    {
        // When
        $method = $this->authentication->authenticate($this->alice, ' k7q2m x9pl4 ', Fixtures::context($this->clock->now()));

        // Then
        static::assertSame('otp', $method->value);
        static::assertTrue($this->totp->backupCodes[0]->isSpent());
    }

    /**
     * Every unspent backup code is compared, whatever the first one that matches.
     */
    #[Test]
    public function everyUnspentBackupCodeIsComparedTo(): void
    {
        // Given
        $this->totp->spendBackupCode(9, $this->clock->now()->modify('-1 day'));

        // When
        $this->authentication->authenticate($this->alice, Totps::BACKUP_CODES[0], Fixtures::context($this->clock->now()));

        // Then
        static::assertCount(9, $this->hasher->verifiedAgainst);
    }

    #[Test]
    public function aWrongBackupCodeIsRefused(): void
    {
        // When
        $exception = $this->failToAuthenticate('ZZZZZ-ZZZZZ');

        // Then
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
        static::assertSame([], array_filter($this->totp->backupCodes, static fn (BackupCode $code): bool => $code->isSpent()));
    }

    /**
     * Decision 0006: five attempts a minute, the sixth refused before anything is verified, a right code included.
     */
    #[Test]
    public function theSixthAttemptIsRefusedWhateverTheCode(): void
    {
        // Given
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->failToAuthenticate('000000');
        }

        // When
        $exception = $this->failToAuthenticate(Totps::codeAt($this->clock->now()));

        // Then
        static::assertSame(AuthenticationFailureReason::TooManyAttempts, $exception->reason);
        static::assertNull($this->totp->lastUsedAt);
        static::assertCount(6, $this->attempts->attempts);
    }

    #[Test]
    public function anAcceptedCodeCountsAsAnAttempt(): void
    {
        // When
        $this->authentication->authenticate($this->alice, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame([$this->alice->id->toRfc4122()], $this->attempts->attempts);
    }

    #[Test]
    public function aUserWithoutATotpIsRefused(): void
    {
        // Given
        $bob = Fixtures::user($this->alice->tenant, 'bob', 'bob-subject');

        // When
        $exception = $this->failToAuthenticate('000000', $bob);

        // Then
        static::assertSame(AuthenticationFailureReason::NoSuchCredential, $exception->reason);
    }

    #[Test]
    public function aRevokedTotpIsNoTotp(): void
    {
        // Given
        $this->totp->revoke($this->clock->now());

        // When
        $exception = $this->failToAuthenticate(Totps::codeAt($this->clock->now()));

        // Then
        static::assertSame(AuthenticationFailureReason::NoSuchCredential, $exception->reason);
    }

    #[Test]
    public function aDisabledUserIsRefusedAfterTheCodeWasChecked(): void
    {
        // Given
        $this->alice->disable($this->clock->now());

        // When
        $exception = $this->failToAuthenticate(Totps::codeAt($this->clock->now()));

        // Then
        static::assertSame(AuthenticationFailureReason::DisabledUser, $exception->reason);
        static::assertNull($this->totp->lastUsedAt);
        static::assertSame([], $this->events->of(TotpUsed::class));
    }

    #[Test]
    public function aFailureIsAnnouncedWithTheUserTheMethodAndTheContext(): void
    {
        // Given
        $context = Fixtures::context($this->clock->now());

        // When
        $this->failToAuthenticate('000000', context: $context);

        // Then
        static::assertCount(1, $this->events->events);
        $failed = $this->events->of(AuthenticationFailed::class)[0];
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $failed->reason);
        static::assertSame('otp', $failed->method?->value);
        static::assertSame('alice', $failed->identifier);
        static::assertSame($this->alice, $failed->user);
        static::assertSame($this->alice->tenant, $failed->tenant);
        static::assertSame($context, $failed->context);
        static::assertEquals($this->clock->now(), $failed->occurredAt);
    }

    #[Test]
    public function aWrongCodeRecordsNoUse(): void
    {
        // When
        $this->failToAuthenticate('000000');

        // Then
        static::assertNull($this->totp->lastUsedAt);
        static::assertSame(Totps::stepAt($this->clock->now()->modify('-1 hour')), $this->totp->lastAcceptedStep);
    }

    private function failToAuthenticate(string $code, ?User $user = null, ?RequestContext $context = null): AuthenticationFailedException
    {
        try {
            $this->authentication->authenticate($user ?? $this->alice, $code, $context ?? Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException $exception) {
            return $exception;
        }

        static::fail('Authentication should have failed.');
    }
}
