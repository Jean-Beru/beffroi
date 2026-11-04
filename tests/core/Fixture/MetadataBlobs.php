<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function json_encode;
use const JSON_THROW_ON_ERROR;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;

/**
 * FIDO Metadata Service v3.1.1 §3.1.6
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
     * @param list<string> $statuses in the order the service issued them
     * @param list<string> $attestationRootCertificates DER in base64
     * @param list<string> $omitting
     * @param string|null $icon a data: URL
     *
     * @return array<string, mixed>
     */
    public static function entry(
        string $aaguid,
        array $statuses = [AuthenticatorStatus::FIDO_CERTIFIED],
        string $description = 'Authenticator of the tests',
        array $attestationRootCertificates = [],
        array $omitting = [],
        ?string $icon = null,
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
        if ($icon !== null) {
            $statement['icon'] = $icon;
        }
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
