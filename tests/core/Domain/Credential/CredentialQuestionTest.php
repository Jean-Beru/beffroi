<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use function array_map;
use Beffroi\Core\Domain\Credential\AuthenticatorTransport;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Credential\CredentialQuestion;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Listing\Period;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.2
 */
final class CredentialQuestionTest extends TestCase
{
    private const string YUBIKEY = 'cb69481e-8ff7-4039-93ec-0a2729a154a8';

    #[Test]
    public function aQuestionThatAsksNothingAdmitsEveryCredential(): void
    {
        // Given
        $revoked = Fixtures::passkey();
        $revoked->revoke(Fixtures::now());

        // When / Then
        static::assertSame([true, true, true], array_map(new CredentialQuestion()->admits(...), [Fixtures::passkey(), $revoked, Fixtures::password()]));
    }

    #[Test]
    public function theRevokedOnesComeAfterTheOthersEachInTheOrderGiven(): void
    {
        // Given
        $first = Fixtures::passkey(name: 'first');
        $second = Fixtures::passkey(name: 'second');
        $third = Fixtures::passkey(name: 'third');
        $fourth = Fixtures::passkey(name: 'fourth');
        $first->revoke(Fixtures::now());
        $third->revoke(Fixtures::now());

        // When
        $narrowed = new CredentialQuestion()->narrow([$first, $second, $third, $fourth]);

        // Then
        static::assertSame(['second', 'fourth', 'first', 'third'], array_map(static fn (PasskeyCredential $passkey): string => $passkey->name, $narrowed));
    }

    #[Test]
    #[DataProvider('provideStates')]
    public function theStateAskedForIsTheOneAdmitted(bool $revoked, bool $admitsTheRevoked, bool $admitsTheActive): void
    {
        // Given
        $question = new CredentialQuestion(revoked: $revoked);
        $gone = Fixtures::passkey();
        $gone->revoke(Fixtures::now());

        // When / Then
        static::assertSame([$admitsTheRevoked, $admitsTheActive], [$question->admits($gone), $question->admits(Fixtures::passkey())]);
    }

    /**
     * @return iterable<string, array{bool, bool, bool}>
     */
    public static function provideStates(): iterable
    {
        yield 'the revoked ones' => [true, true, false];
        yield 'the others' => [false, false, true];
    }

    #[Test]
    public function aCredentialThatCannotBeRevokedIsAmongTheOthers(): void
    {
        // When / Then
        static::assertTrue(new CredentialQuestion(revoked: false)->admits(Fixtures::password()));
    }

    #[Test]
    #[DataProvider('provideEnrolments')]
    public function theDaysOfEnrolmentAdmitWhatWasEnrolledOnThem(string $enrolledAt, bool $admitted): void
    {
        // Given
        $question = new CredentialQuestion(enrolled: Period::ofDays(Fixtures::now(), Fixtures::now()));

        // When / Then
        static::assertSame($admitted, $question->admits(Fixtures::passkey(createdAt: Fixtures::now()->modify($enrolledAt))));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideEnrolments(): iterable
    {
        yield 'that day' => ['+1 hour', true];
        yield 'the day before' => ['-1 day', false];
    }

    #[Test]
    #[DataProvider('provideUses')]
    public function theDaysOfUseAdmitWhatWasLastUsedOnThem(string $usedAt, bool $admitted): void
    {
        // Given
        $question = new CredentialQuestion(used: Period::ofDays(Fixtures::now(), Fixtures::now()));
        $passkey = Fixtures::passkey(createdAt: Fixtures::now()->modify('-1 month'));
        $passkey->recordUse(Fixtures::authenticatorData(signCount: 1), Fixtures::now()->modify($usedAt));

        // When / Then
        static::assertSame($admitted, $question->admits($passkey));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideUses(): iterable
    {
        yield 'that day' => ['+1 hour', true];
        yield 'the day before' => ['-1 day', false];
    }

    #[Test]
    public function aCredentialNeverUsedIsInNoPeriodOfUse(): void
    {
        // Given
        $question = new CredentialQuestion(used: Period::ofDays(null, Fixtures::now()));

        // When / Then
        static::assertFalse($question->admits(Fixtures::passkey()));
    }

    /**
     * WebAuthn Level 3 §6.5.1
     */
    #[Test]
    #[DataProvider('provideModels')]
    public function theModelAskedForAdmitsTheCredentialsThatDeclareIt(Credential $credential, bool $admitted): void
    {
        // Given
        $question = new CredentialQuestion(model: Uuid::fromString(self::YUBIKEY));

        // When / Then
        static::assertSame($admitted, $question->admits($credential));
    }

    /**
     * @return iterable<string, array{Credential, bool}>
     */
    public static function provideModels(): iterable
    {
        yield 'a passkey of that model' => [Fixtures::passkey(aaguid: Uuid::fromString(self::YUBIKEY)), true];
        yield 'a passkey of another model' => [Fixtures::passkey(aaguid: Uuid::v4()), false];
        yield 'a credential that declares no model' => [Fixtures::password(), false];
    }

    /**
     * WebAuthn Level 3 §6.1.3
     */
    #[Test]
    #[DataProvider('provideSynchronisations')]
    public function theSynchronisationAskedForAdmitsTheCredentialsThatHaveIt(bool $synced, Credential $credential, bool $admitted): void
    {
        // Given
        $question = new CredentialQuestion(synced: $synced);

        // When / Then
        static::assertSame($admitted, $question->admits($credential));
    }

    /**
     * @return iterable<string, array{bool, Credential, bool}>
     */
    public static function provideSynchronisations(): iterable
    {
        yield 'a synced passkey asked synced' => [true, Fixtures::passkey(backupEligible: true), true];
        yield 'a device-bound passkey asked synced' => [true, Fixtures::passkey(), false];
        yield 'a device-bound passkey asked device-bound' => [false, Fixtures::passkey(), true];
        yield 'a synced passkey asked device-bound' => [false, Fixtures::passkey(backupEligible: true), false];
        yield 'a credential that says neither' => [false, Fixtures::password(), false];
    }

    /**
     * WebAuthn Level 3 §5.8.4
     */
    #[Test]
    #[DataProvider('provideTransports')]
    public function theWayAskedForAdmitsTheCredentialsReachedThroughIt(Credential $credential, bool $admitted): void
    {
        // Given
        $question = new CredentialQuestion(reachedThrough: AuthenticatorTransport::Nfc);

        // When / Then
        static::assertSame($admitted, $question->admits($credential));
    }

    /**
     * @return iterable<string, array{Credential, bool}>
     */
    public static function provideTransports(): iterable
    {
        yield 'a passkey reached through it among others' => [Fixtures::passkey(transports: ['usb', 'nfc']), true];
        yield 'a passkey reached otherwise' => [Fixtures::passkey(transports: ['usb']), false];
        yield 'a credential that is not reached' => [Fixtures::password(), false];
    }
}
