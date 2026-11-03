<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Security;

use DateTimeImmutable;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Core\Application\Authentication\AuthenticationFailedException;
use Beffroi\Core\Application\Totp\TotpAuthentication;
use Beffroi\Core\Application\Totp\TotpEnrolment;
use Beffroi\Core\Domain\Credential\BackupCode;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Credential\TotpSecret;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CodeAttemptLimiterInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Port\TotpAlgorithmInterface;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Totps;
use function intdiv;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.4, decision 0006: the attempts at a code are counted by the rate limiter of Symfony
 * the provider declares, five in a sliding window of a minute, the sixth refused whatever the code; the
 * TOTP enrolled and verified through the services of the kernel, the secret sealed by its KMS.
 */
final class TotpAttemptsTest extends DatabaseTestCase
{
    private User $alice;

    private TotpSecret $secret;

    /**
     * A TOTP enrolled an hour ago on the secret of RFC 6238, sealed by the KMS of the kernel; the backup
     * codes hashed by the hasher of the suite, the tests that verify one enrolling through the kernel.
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->alice = self::user();
        $this->secret = Totps::secret();
        $sealed = self::service('test.beffroi.secret_sealer', SecretSealerInterface::class)->seal(self::tenant(), $this->secret->bytes);
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->save(
                new TotpCredential(
                    Uuid::v7(),
                    $this->alice,
                    $sealed,
                    Totps::credential($this->alice, new FakePasswordHasher())->backupCodes,
                    intdiv(new DateTimeImmutable('-1 hour')->getTimestamp(), TotpCredential::PERIOD),
                    new DateTimeImmutable('-1 hour'),
                ),
            );
    }

    /**
     * The whole enrolment through the services of the kernel: the secret sealed by its KMS, the backup
     * codes hashed by its hasher, the step of the first code spent.
     */
    #[Test]
    public function theEnrolmentThroughTheKernelSealsTheSecretUnderItsKmsAndHashesTheCodes(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $provisioning = self::enrolment()->begin($bob);
        $this->secret = $provisioning->secret;
        $aStepAgo = new DateTimeImmutable('-30 seconds');

        // When
        $totp = self::enrolment()->complete($bob, $provisioning, $this->codeAt($aStepAgo), self::context());

        // Then
        static::assertStringNotContainsString($provisioning->secret->bytes, $totp->sealedSecret);
        static::assertSame(
            $provisioning->secret->bytes,
            self::service('test.beffroi.secret_sealer', SecretSealerInterface::class)->unseal(self::tenant(), $totp->sealedSecret),
        );
        static::assertSame(intdiv($aStepAgo->getTimestamp(), TotpCredential::PERIOD), $totp->lastAcceptedStep);
        static::assertSame(Argon2id::NAME, $totp->backupCodes[0]->hash->algorithm->name());
        static::assertTrue(
            self::service('test.beffroi.password_hasher', PasswordHasherInterface::class)
                ->verify($totp->backupCodes[0]->hash, BackupCode::normalize($provisioning->backupCodes[0])),
        );
        static::assertSame(
            $totp,
            self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($bob, TotpCredential::class)[0] ?? null,
        );
    }

    #[Test]
    public function aCodeOfTheAuthenticatorIsAccepted(): void
    {
        // When
        $method = self::authentication()->authenticate($this->alice, $this->codeAt(new DateTimeImmutable()), self::context());

        // Then
        static::assertSame('otp', $method->value);
    }

    #[Test]
    public function theSixthAttemptInAMinuteIsRefusedWhateverTheCode(): void
    {
        // Given
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            static::assertSame(AuthenticationFailureReason::InvalidCredential, $this->failToAuthenticate($this->alice, '000000')->reason);
        }

        // When
        $exception = $this->failToAuthenticate($this->alice, $this->codeAt(new DateTimeImmutable()));

        // Then
        static::assertSame(AuthenticationFailureReason::TooManyAttempts, $exception->reason);
    }

    #[Test]
    public function aBackupCodeIsAcceptedThroughTheHasherOfTheKernel(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $provisioning = self::enrolment()->begin($bob);
        $this->secret = $provisioning->secret;
        $totp = self::enrolment()->complete($bob, $provisioning, $this->codeAt(new DateTimeImmutable()), self::context());

        // When
        $method = self::authentication()->authenticate($bob, $provisioning->backupCodes[7], self::context());

        // Then
        static::assertSame('otp', $method->value);
        static::assertTrue($totp->backupCodes[7]->isSpent());
    }

    /**
     * Issue #128: the limit read before the secret is opened counts nothing; the five attempts are still
     * there to be counted.
     */
    #[Test]
    public function readingTheLimitCountsNoAttempt(): void
    {
        // Given
        $attempts = self::service('test.beffroi.code_attempts', CodeAttemptLimiterInterface::class);
        for ($read = 1; $read <= 6; ++$read) {
            static::assertTrue($attempts->mayAttempt($this->alice));
        }

        // When
        $counted = [];
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $counted[] = $attempts->attempt($this->alice);
        }

        // Then
        static::assertSame([true, true, true, true, true], $counted);
    }

    #[Test]
    public function theLimitReadIsTheLimitCounted(): void
    {
        // Given
        $attempts = self::service('test.beffroi.code_attempts', CodeAttemptLimiterInterface::class);
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $attempts->attempt($this->alice);
        }

        // When / Then
        static::assertFalse($attempts->mayAttempt($this->alice));
    }

    #[Test]
    public function theAttemptsOfOneUserDoNotCountForAnother(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->failToAuthenticate($this->alice, '000000');
        }

        // When
        $exception = $this->failToAuthenticate($bob, '000000');

        // Then
        static::assertSame(AuthenticationFailureReason::NoSuchCredential, $exception->reason);
    }

    private function codeAt(DateTimeImmutable $at): string
    {
        return self::service('test.beffroi.totp_algorithm', TotpAlgorithmInterface::class)
            ->codeAt($this->secret, intdiv($at->getTimestamp(), TotpCredential::PERIOD));
    }

    private function failToAuthenticate(User $user, string $code): AuthenticationFailedException
    {
        try {
            self::authentication()->authenticate($user, $code, self::context());
        } catch (AuthenticationFailedException $exception) {
            return $exception;
        }

        static::fail('Authentication should have failed.');
    }

    private static function enrolment(): TotpEnrolment
    {
        return self::service('test.beffroi.totp_enrolment', TotpEnrolment::class);
    }

    private static function authentication(): TotpAuthentication
    {
        return self::service('test.beffroi.totp_authentication', TotpAuthentication::class);
    }
}
