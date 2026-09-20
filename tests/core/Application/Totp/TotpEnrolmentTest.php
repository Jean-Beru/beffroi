<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Totp;

use function array_unique;
use Heidi\Core\Application\Totp\ActiveTotp;
use Heidi\Core\Application\Totp\TotpCodeMatcher;
use Heidi\Core\Application\Totp\TotpEnrolment;
use Heidi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Heidi\Core\Domain\Credential\BackupCode;
use Heidi\Core\Domain\Credential\TotpCredential;
use Heidi\Core\Domain\Event\CredentialEnrolled;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Exception\CredentialEnrolmentFailedException;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Core\Tests\Fixture\Totps;
use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function rawurlencode;
use Symfony\Component\Clock\MockClock;

/**
 * Architecture §3.4: a TOTP enrolled in two steps from a session the user already holds, the credential
 * existing only once a first code was verified (RFC 6238 §5.2).
 */
final class TotpEnrolmentTest extends TestCase
{
    private User $alice;

    private InMemoryCredentialRepository $credentials;

    private FakePasswordHasher $hasher;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private TotpEnrolment $enrolment;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->credentials = new InMemoryCredentialRepository();
        $this->hasher = new FakePasswordHasher();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-20T12:00:15+00:00');
        $this->enrolment = new TotpEnrolment($this->credentials, new ActiveTotp($this->credentials), Totps::algorithm(), new TotpCodeMatcher(Totps::algorithm()), Totps::sealer(), $this->hasher, $this->clock, $this->events);
    }

    /**
     * The Key Uri Format: the tenant is the issuer, the username the account, the secret the one of the
     * provisioning in base32.
     */
    #[Test]
    public function theProvisioningNamesTheTenantTheUserAndAFreshSecret(): void
    {
        // When
        $provisioning = $this->enrolment->begin($this->alice);

        // Then
        static::assertSame('otpauth://totp/Acme%3Aalice?issuer=Acme&secret=' . Base32::encodeUpperUnpadded($provisioning->secret->bytes), $provisioning->uri);
        static::assertNotSame($provisioning->secret->bytes, $this->enrolment->begin($this->alice)->secret->bytes);
    }

    #[Test]
    public function theProvisioningIssuesTenDistinctBackupCodes(): void
    {
        // When
        $provisioning = $this->enrolment->begin($this->alice);

        // Then
        static::assertCount(10, $provisioning->backupCodes);
        static::assertCount(10, array_unique($provisioning->backupCodes));
        foreach ($provisioning->backupCodes as $code) {
            static::assertSame(1, preg_match('/^[A-Z2-7]{5}-[A-Z2-7]{5}$/', $code));
        }
    }

    #[Test]
    public function anEnrolmentAbandonedAfterTheProvisioningLeavesNothing(): void
    {
        // When
        $this->enrolment->begin($this->alice);

        // Then
        static::assertSame([], $this->credentials->findByUser($this->alice));
        static::assertSame([], $this->events->events);
    }

    #[Test]
    public function aUserWithAnActiveTotpGetsNoProvisioning(): void
    {
        // Given
        $this->credentials->save(Totps::credential($this->alice, $this->hasher));

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('The user has a TOTP already; it is revoked before another is enrolled.');

        // When
        $this->enrolment->begin($this->alice);
    }

    #[Test]
    public function aUserWhoseTotpWasRevokedEnrolsAnother(): void
    {
        // Given
        $revoked = Totps::credential($this->alice, $this->hasher);
        $revoked->revoke(Fixtures::now());
        $this->credentials->save($revoked);

        // When
        $provisioning = $this->enrolment->begin($this->alice);

        // Then
        static::assertStringStartsWith('otpauth://totp/Acme%3Aalice?', $provisioning->uri);
        static::assertNotSame(Totps::SEED, $provisioning->secret->bytes);
    }

    #[Test]
    public function aFirstCodeThatHoldsCreatesTheCredentialSealedAndHashed(): void
    {
        // Given
        $provisioning = $this->enrolment->begin($this->alice);
        $context = Fixtures::context($this->clock->now());

        // When
        $totp = $this->enrolment->complete($this->alice, $provisioning, Totps::codeAt($this->clock->now(), $provisioning->secret), $context);

        // Then
        static::assertSame($this->alice, $totp->user);
        static::assertSame($provisioning->secret->bytes, Totps::sealer()->unseal($this->alice->tenant, $totp->sealedSecret));
        static::assertSame(Totps::stepAt($this->clock->now()), $totp->lastAcceptedStep);
        static::assertEquals($this->clock->now(), $totp->createdAt);
        static::assertNull($totp->lastUsedAt);
        static::assertCount(10, $totp->backupCodes);
        foreach ($provisioning->backupCodes as $index => $code) {
            static::assertTrue($this->hasher->verify($totp->backupCodes[$index]->hash, BackupCode::normalize($code)));
            static::assertFalse($totp->backupCodes[$index]->isSpent());
        }
        static::assertSame([$totp], $this->credentials->findByUser($this->alice, TotpCredential::class));
    }

    #[Test]
    public function theFirstCodeIsSpentByTheEnrolment(): void
    {
        // Given
        $provisioning = $this->enrolment->begin($this->alice);

        // When
        $totp = $this->enrolment->complete($this->alice, $provisioning, Totps::codeAt($this->clock->now(), $provisioning->secret), Fixtures::context($this->clock->now()));

        // Then
        static::assertFalse($totp->acceptsStep(Totps::stepAt($this->clock->now())));
    }

    #[Test]
    public function aFirstCodeOnePeriodEarlyHolds(): void
    {
        // Given
        $provisioning = $this->enrolment->begin($this->alice);
        $early = $this->clock->now()
            ->modify('-30 seconds');

        // When
        $totp = $this->enrolment->complete($this->alice, $provisioning, Totps::codeAt($early, $provisioning->secret), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame(Totps::stepAt($early), $totp->lastAcceptedStep);
    }

    #[Test]
    public function theEnrolmentIsAnnouncedWithItsContext(): void
    {
        // Given
        $provisioning = $this->enrolment->begin($this->alice);
        $context = Fixtures::context($this->clock->now());

        // When
        $totp = $this->enrolment->complete($this->alice, $provisioning, Totps::codeAt($this->clock->now(), $provisioning->secret), $context);

        // Then
        static::assertCount(1, $this->events->events);
        $enrolled = $this->events->of(CredentialEnrolled::class)[0];
        static::assertSame($totp, $enrolled->credential);
        static::assertSame($context, $enrolled->context);
        static::assertEquals($this->clock->now(), $enrolled->occurredAt);
    }

    #[Test]
    public function aFirstCodeThatDoesNotHoldIsRefused(): void
    {
        // Given
        $provisioning = $this->enrolment->begin($this->alice);

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('The code does not match the secret.');

        // When
        $this->enrolment->complete($this->alice, $provisioning, Totps::codeAt($this->clock->now()->modify('-2 minutes'), $provisioning->secret), Fixtures::context($this->clock->now()));
    }

    #[Test]
    public function aRefusedFirstCodeLeavesNothing(): void
    {
        // Given
        $provisioning = $this->enrolment->begin($this->alice);

        // When
        try {
            $this->enrolment->complete($this->alice, $provisioning, '000000', Fixtures::context($this->clock->now()));
        } catch (CredentialEnrolmentFailedException) {
        }

        // Then
        static::assertSame([], $this->credentials->findByUser($this->alice));
        static::assertSame([], $this->events->events);
        static::assertSame(0, $this->hasher->hashed);
    }

    /**
     * Two enrolments begun side by side: the second one to complete finds the first one's credential.
     */
    #[Test]
    public function aSecondActiveTotpIsRefusedAtCompletion(): void
    {
        // Given
        $provisioning = $this->enrolment->begin($this->alice);
        $this->credentials->save(Totps::credential($this->alice, $this->hasher));

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('The user has a TOTP already; it is revoked before another is enrolled.');

        // When
        $this->enrolment->complete($this->alice, $provisioning, Totps::codeAt($this->clock->now(), $provisioning->secret), Fixtures::context($this->clock->now()));
    }

    #[Test]
    public function theAccountOfTheUriIsTheUsernameAsTyped(): void
    {
        // Given
        $bob = Fixtures::user(username: 'bob.o');

        // When
        $provisioning = $this->enrolment->begin($bob);

        // Then
        static::assertStringStartsWith('otpauth://totp/' . rawurlencode('Acme:bob.o') . '?', $provisioning->uri);
        static::assertCount(0, $this->credentials->findByUser($bob));
    }
}
