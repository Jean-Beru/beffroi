<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use function chr;
use function hash;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use LogicException;
use function pack;
use ParagonIE\ConstantTime\Base64UrlSafe;
use function random_bytes;
use function str_repeat;
use function strlen;
use Webauthn\AuthenticatorData;

/**
 * WebAuthn Level 3 §6
 */
final class SoftwareAuthenticator
{
    public readonly string $credentialId;

    public readonly string $aaguid;

    /**
     * @var non-empty-string
     */
    public private(set) string $userHandle = '-';

    public private(set) int $signCount = 0;

    /**
     * @param string $attestation "none" or "packed"
     * @param string|null $aaguid sixteen bytes
     * @param AttestationCertificate|null $attestedBy the certificate a "packed" attestation is signed with, self attestation without one
     */
    public function __construct(
        private string $origin,
        private ?string $relyingPartyId = null,
        private bool $userPresent = true,
        private bool $userVerified = false,
        private bool $backupEligible = false,
        private bool $backedUp = false,
        private string $attestation = 'none',
        private bool $forgesAttestation = false,
        private SoftwareCredentialKey $credentialKey = new Es256SoftwareKey(),
        ?string $aaguid = null,
        private ?AttestationCertificate $attestedBy = null,
    ) {
        $this->credentialId = random_bytes(32);
        $this->aaguid = $aaguid ?? random_bytes(16);
    }

    public function atOrigin(string $origin): self
    {
        $clone = clone $this;
        $clone->origin = $origin;

        return $clone;
    }

    public function forRelyingParty(string $relyingPartyId): self
    {
        $clone = clone $this;
        $clone->relyingPartyId = $relyingPartyId;

        return $clone;
    }

    /**
     * WebAuthn Level 3 §6.1.3
     */
    public function withoutBackupEligibility(): self
    {
        $clone = clone $this;
        $clone->backupEligible = false;
        $clone->backedUp = false;

        return $clone;
    }

    /**
     * WebAuthn Level 3 §6.1.1
     */
    public function withSignCount(int $signCount): self
    {
        $clone = clone $this;
        $clone->signCount = $signCount;

        return $clone;
    }

    /**
     * WebAuthn Level 3 §6.3.2
     */
    public function create(string $creationOptions): string
    {
        $options = self::decode($creationOptions);
        $rp = $options['rp'] ?? null;
        $user = $options['user'] ?? null;
        $userHandle = is_array($user) && is_string($user['id'] ?? null) ? Base64UrlSafe::decodeNoPadding($user['id']) : '';
        if ($userHandle === '') {
            throw new LogicException('The creation options name no user.');
        }
        $this->userHandle = $userHandle;
        $relyingPartyId =
            $this->relyingPartyId
            ?? (is_array($rp) && is_string($rp['id'] ?? null) ? $rp['id'] : throw new LogicException('The creation options name no relying party.'));
        $attestedCredentialData = $this->aaguid . pack('n', strlen($this->credentialId)) . $this->credentialId . $this->cosePublicKey();
        $authenticatorData = $this->authenticatorData($relyingPartyId, AuthenticatorData::FLAG_AT, $attestedCredentialData);
        $clientDataJson = $this->clientDataJson('webauthn.create', self::challenge($options));
        $attestationObject = (string) MapObject::create([
            MapItem::create(TextStringObject::create('fmt'), TextStringObject::create($this->attestation)),
            MapItem::create(TextStringObject::create('attStmt'), $this->attestationStatement($authenticatorData . hash('sha256', $clientDataJson, true))),
            MapItem::create(TextStringObject::create('authData'), ByteStringObject::create($authenticatorData)),
        ]);

        return json_encode([
            'id' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'rawId' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64UrlSafe::encodeUnpadded($clientDataJson),
                'attestationObject' => Base64UrlSafe::encodeUnpadded($attestationObject),
                'transports' => [$this->backupEligible ? 'internal' : 'usb'],
            ],
            'clientExtensionResults' => [],
            'authenticatorAttachment' => $this->backupEligible ? 'platform' : 'cross-platform',
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * WebAuthn Level 3 §6.3.3
     */
    public function get(string $requestOptions): string
    {
        $options = self::decode($requestOptions);
        $relyingPartyId =
            $this->relyingPartyId
            ?? (is_string($options['rpId'] ?? null) ? $options['rpId'] : throw new LogicException('The request options name no relying party.'));
        if (! $this->backupEligible) {
            ++$this->signCount;
        }
        $clientDataJson = $this->clientDataJson('webauthn.get', self::challenge($options));
        $authenticatorData = $this->authenticatorData($relyingPartyId, 0, '');
        $signature = $this->credentialKey->sign($authenticatorData . hash('sha256', $clientDataJson, true));

        return json_encode([
            'id' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'rawId' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64UrlSafe::encodeUnpadded($clientDataJson),
                'authenticatorData' => Base64UrlSafe::encodeUnpadded($authenticatorData),
                'signature' => Base64UrlSafe::encodeUnpadded($signature),
                'userHandle' => Base64UrlSafe::encodeUnpadded($this->userHandle),
            ],
            'clientExtensionResults' => [],
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * RFC 9053 §7
     */
    public function cosePublicKey(): string
    {
        return $this->credentialKey->cosePublicKey();
    }

    /**
     * WebAuthn Level 3 §8.2, §8.7
     */
    private function attestationStatement(string $data): MapObject
    {
        if ($this->attestation !== 'packed') {
            return MapObject::create();
        }
        $signer = $this->attestedBy ?? $this->credentialKey;
        $signature = $signer->sign($data);
        $members = [
            MapItem::create(TextStringObject::create('alg'), NegativeIntegerObject::create($signer->algorithm())),
            MapItem::create(
                TextStringObject::create('sig'),
                ByteStringObject::create($this->forgesAttestation ? str_repeat("\0", strlen($signature)) : $signature),
            ),
        ];
        if ($this->attestedBy !== null) {
            $members[] = MapItem::create(TextStringObject::create('x5c'), ListObject::create([ByteStringObject::create($this->attestedBy->der)]));
        }

        return MapObject::create($members);
    }

    /**
     * WebAuthn Level 3 §6.1
     */
    private function authenticatorData(string $relyingPartyId, int $flags, string $trailer): string
    {
        $flags |=
            ($this->userPresent ? AuthenticatorData::FLAG_UP : 0)
            | ($this->userVerified ? AuthenticatorData::FLAG_UV : 0)
            | ($this->backupEligible ? AuthenticatorData::FLAG_BE : 0)
            | ($this->backedUp ? AuthenticatorData::FLAG_BS : 0);

        return hash('sha256', $relyingPartyId, true) . chr($flags & 0xFF) . pack('N', $this->signCount) . $trailer;
    }

    /**
     * WebAuthn Level 3 §5.8.1
     */
    private function clientDataJson(string $type, string $challenge): string
    {
        return json_encode([
            'type' => $type,
            'challenge' => $challenge,
            'origin' => $this->origin,
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * @param array<array-key, mixed> $options
     */
    private static function challenge(array $options): string
    {
        return is_string($options['challenge'] ?? null) ? $options['challenge'] : throw new LogicException('The options carry no challenge.');
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function decode(string $json): array
    {
        $decoded = json_decode($json, true, 8, JSON_THROW_ON_ERROR);

        return is_array($decoded) ? $decoded : throw new LogicException('The options are not a JSON object.');
    }
}
