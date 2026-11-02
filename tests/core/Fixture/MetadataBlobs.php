<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function json_encode;
use const JSON_THROW_ON_ERROR;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;

/**
 * Payloads of a Metadata BLOB (FIDO Metadata Service v3.1.1 §3.1.6) for the tests: one entry per
 * authenticator, with the statement an authenticator of the tests would have and the status reports the
 * test chooses.
 */
final class MetadataBlobs
{
    /**
     * @param list<array<string, mixed>> $entries
     */
    public static function payload(array $entries, int $serialNumber = 1, string $nextUpdate = '2026-10-01'): string
    {
        return json_encode([
            'legalHeader' => 'For the tests.',
            'no' => $serialNumber,
            'nextUpdate' => $nextUpdate,
            'entries' => $entries,
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * @param list<string> $statuses the status reports, in the order the service issued them
     * @param list<string> $attestationRootCertificates DER in base64
     * @param list<string> $omitting the members of the statement it leaves out, those FIDO Metadata Statement
     *                               v3.1 §4 does not require
     *
     * @return array<string, mixed>
     */
    public static function entry(
        string $aaguid,
        array $statuses = [AuthenticatorStatus::FIDO_CERTIFIED],
        string $description = 'Authenticator of the tests',
        array $attestationRootCertificates = [],
        array $omitting = [],
    ): array {
        $reports = [];
        foreach ($statuses as $status) {
            $reports[] = [
                'status' => $status,
                'effectiveDate' => '2026-09-01',
            ];
        }
        $statement = [
            'legalHeader' => 'For the tests.',
            'aaguid' => $aaguid,
            'description' => $description,
            'authenticatorVersion' => 1,
            'protocolFamily' => 'fido2',
            'schema' => 3,
            'upv' => [[
                'major' => 1,
                'minor' => 0,
            ]],
            'authenticationAlgorithms' => ['secp256r1_ecdsa_sha256_raw'],
            'publicKeyAlgAndEncodings' => ['cose'],
            'attestationTypes' => ['basic_full', 'basic_surrogate'],
            'userVerificationDetails' => [[[
                'userVerificationMethod' => 'presence_internal',
            ]]],
            'keyProtection' => ['hardware'],
            'matcherProtection' => ['on_chip'],
            'attachmentHint' => ['external'],
            'tcDisplay' => [],
            'attestationRootCertificates' => $attestationRootCertificates,
        ];
        foreach ($omitting as $member) {
            unset($statement[$member]);
        }

        return [
            'aaguid' => $aaguid,
            'metadataStatement' => $statement,
            'statusReports' => $reports,
            'timeOfLastStatusChange' => '2026-09-01',
        ];
    }
}
