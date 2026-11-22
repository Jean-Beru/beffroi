<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Domain\Credential\FidoCertification;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;

/**
 * FIDO Metadata Service v3.1.1 §3.1.4, §3.1.4.1
 */
final class FidoCertificationTest extends TestCase
{
    /**
     * @param list<string> $statuses in the order the service issued them
     */
    #[Test]
    #[DataProvider('provideReports')]
    public function theCertificationIsTheLastOneTheReportsState(array $statuses, FidoCertification $certification): void
    {
        // When / Then
        static::assertSame($certification, FidoCertification::lastOf($statuses));
    }

    /**
     * @return iterable<string, array{list<string>, FidoCertification}>
     */
    public static function provideReports(): iterable
    {
        yield 'one certification' => [[AuthenticatorStatus::FIDO_CERTIFIED_L1], FidoCertification::Level1];
        yield 'the later of two certifications' => [[AuthenticatorStatus::FIDO_CERTIFIED, AuthenticatorStatus::FIDO_CERTIFIED_L2], FidoCertification::Level2];
        yield 'an update available after it (§3.1.4.3)' => [
            [AuthenticatorStatus::FIDO_CERTIFIED_L1, AuthenticatorStatus::UPDATE_AVAILABLE],
            FidoCertification::Level1,
        ];
        yield 'a security notification after it (§3.1.4.2)' => [
            [AuthenticatorStatus::FIDO_CERTIFIED_L1plus, AuthenticatorStatus::USER_VERIFICATION_BYPASS],
            FidoCertification::Level1Plus,
        ];
        yield 'a FIPS 140 certification after it, another scheme' => [
            [AuthenticatorStatus::FIDO_CERTIFIED_L2plus, 'FIPS140_CERTIFIED_L2'],
            FidoCertification::Level2Plus,
        ];
        yield 'a status the specification does not define after it' => [
            [AuthenticatorStatus::FIDO_CERTIFIED_L3, 'FIDO_CERTIFIED_L9'],
            FidoCertification::Level3,
        ];
        yield 'retired by its vendor after it' => [[AuthenticatorStatus::FIDO_CERTIFIED_L2, 'RETIRED'], FidoCertification::Retired];
        yield 'revoked after it' => [[AuthenticatorStatus::FIDO_CERTIFIED_L3plus, AuthenticatorStatus::REVOKED], FidoCertification::Revoked];
        yield 'not certified' => [[AuthenticatorStatus::NOT_FIDO_CERTIFIED], FidoCertification::NotCertified];
        yield 'a self-assessment submitted' => [[AuthenticatorStatus::SELF_ASSERTION_SUBMITTED], FidoCertification::SelfAssertionSubmitted];
    }

    /**
     * @param list<string> $statuses
     */
    #[Test]
    #[DataProvider('provideReportsThatStateNoCertification')]
    public function reportsThatStateNoCertificationLeaveNone(array $statuses): void
    {
        // When / Then
        static::assertNull(FidoCertification::lastOf($statuses));
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function provideReportsThatStateNoCertification(): iterable
    {
        yield 'no report' => [[]];
        yield 'an update and a security notification' => [[AuthenticatorStatus::UPDATE_AVAILABLE, AuthenticatorStatus::ATTESTATION_KEY_COMPROMISE]];
    }
}
