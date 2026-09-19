<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Fixture;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use function chr;
use function hash;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use LogicException;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_EC;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function openssl_sign;
use OpenSSLAsymmetricKey;
use function pack;
use ParagonIE\ConstantTime\Base64UrlSafe;
use function random_bytes;
use function str_pad;
use const STR_PAD_LEFT;
use function str_repeat;
use function strlen;
use Webauthn\AuthenticatorData;

/**
 * A FIDO2 authenticator in software, for the tests (WebAuthn Level 3 §6): one P-256 key pair, one
 * credential, the flags chosen by the test. It answers the options as a browser hands them to it
 * (§5.1.8, the JSON of parseCreationOptionsFromJSON and parseRequestOptionsFromJSON) with the JSON a
 * browser hands back (§5.1, toJSON): an attestation object of format "none" at creation, a signed
 * assertion afterwards. A hardware key counts its signatures, a synced passkey keeps the count at zero.
 */
final class SoftwareAuthenticator
{
    public readonly string $credentialId;

    public readonly string $aaguid;

    /**
     * @var non-empty-string the user handle the creation options carried, sent back with every assertion (§6.3.2.1)
     */
    public private(set) string $userHandle = '-';

    public private(set) int $signCount = 0;

    private OpenSSLAsymmetricKey $key;

    /**
     * @param string $attestation the format of the attestation statement at creation (§8): "none", what a
     *                            browser sends when the provider asked for none, or "packed" in self
     *                            attestation (§8.2), what an authenticator may send anyway
     * @param bool $forgesAttestation a packed statement whose signature does not hold: the test of a
     *                                statement verified rather than skipped
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
    ) {
        $this->credentialId = random_bytes(32);
        $this->aaguid = random_bytes(16);
        $key = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        if ($key === false) {
            throw new LogicException('OpenSSL could not generate a P-256 key.');
        }
        $this->key = $key;
    }

    /**
     * The same credential presented from another origin: the test of a phished assertion.
     */
    public function atOrigin(string $origin): self
    {
        $clone = clone $this;
        $clone->origin = $origin;

        return $clone;
    }

    /**
     * The same credential scoped to another relying party: the test of a wrong rpId.
     */
    public function forRelyingParty(string $relyingPartyId): self
    {
        $clone = clone $this;
        $clone->relyingPartyId = $relyingPartyId;

        return $clone;
    }

    /**
     * A later assertion with a count that did not grow: a cloned authenticator or a replay (§6.1.1).
     */
    public function withSignCount(int $signCount): self
    {
        $clone = clone $this;
        $clone->signCount = $signCount;

        return $clone;
    }

    /**
     * The registration ceremony on the authenticator's side (§6.3.2): the attestation object with the new
     * credential, of format "none".
     *
     * @param string $creationOptions the JSON the provider gave the browser
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
        $relyingPartyId = $this->relyingPartyId ?? (is_array($rp) && is_string($rp['id'] ?? null) ? $rp['id'] : throw new LogicException('The creation options name no relying party.'));
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
     * The authentication ceremony on the authenticator's side (§6.3.3): the authenticator data and the
     * signature over them and the hash of the client data.
     *
     * @param string $requestOptions the JSON the provider gave the browser
     */
    public function get(string $requestOptions): string
    {
        $options = self::decode($requestOptions);
        $relyingPartyId = $this->relyingPartyId ?? (is_string($options['rpId'] ?? null) ? $options['rpId'] : throw new LogicException('The request options name no relying party.'));
        if (! $this->backupEligible) {
            ++$this->signCount;
        }
        $clientDataJson = $this->clientDataJson('webauthn.get', self::challenge($options));
        $authenticatorData = $this->authenticatorData($relyingPartyId, 0, '');
        $signature = $this->sign($authenticatorData . hash('sha256', $clientDataJson, true));

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
     * The COSE_Key (RFC 9053 §7.1) of the public key, as the authenticator encodes it.
     */
    public function cosePublicKey(): string
    {
        $details = openssl_pkey_get_details($this->key);
        $curve = is_array($details) && is_array($details['ec'] ?? null) ? $details['ec'] : [];
        $x = $curve['x'] ?? null;
        $y = $curve['y'] ?? null;
        if (! is_string($x) || ! is_string($y)) {
            throw new LogicException('OpenSSL could not describe the key.');
        }

        // RFC 9053 §7.1.1: kty EC2 (1: 2), alg ES256 (3: -7), crv P-256 (-1: 1), x (-2), y (-3)
        return (string) MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2)),
            MapItem::create(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7)),
            MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1)),
            MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create(str_pad($x, 32, "\0", STR_PAD_LEFT))),
            MapItem::create(NegativeIntegerObject::create(-3), ByteStringObject::create(str_pad($y, 32, "\0", STR_PAD_LEFT))),
        ]);
    }

    /**
     * §8.2, packed in self attestation: the signature over the same data as an assertion, with the
     * credential key itself; nothing for "none" (§8.7).
     */
    private function attestationStatement(string $data): MapObject
    {
        if ($this->attestation !== 'packed') {
            return MapObject::create();
        }
        $signature = $this->sign($data);

        return MapObject::create([
            MapItem::create(TextStringObject::create('alg'), NegativeIntegerObject::create(-7)),
            MapItem::create(TextStringObject::create('sig'), ByteStringObject::create($this->forgesAttestation ? str_repeat("\0", strlen($signature)) : $signature)),
        ]);
    }

    /**
     * ES256 (RFC 9053 §2.1), as an authenticator signs.
     */
    private function sign(string $data): string
    {
        if (! openssl_sign($data, $signature, $this->key, OPENSSL_ALGO_SHA256) || ! is_string($signature)) {
            throw new LogicException('OpenSSL could not sign.');
        }

        return $signature;
    }

    /**
     * §6.1: rpIdHash, flags, signCount, then what the ceremony appends.
     */
    private function authenticatorData(string $relyingPartyId, int $flags, string $trailer): string
    {
        $flags |= ($this->userPresent ? AuthenticatorData::FLAG_UP : 0)
            | ($this->userVerified ? AuthenticatorData::FLAG_UV : 0)
            | ($this->backupEligible ? AuthenticatorData::FLAG_BE : 0)
            | ($this->backedUp ? AuthenticatorData::FLAG_BS : 0);

        return hash('sha256', $relyingPartyId, true) . chr($flags & 0xFF) . pack('N', $this->signCount) . $trailer;
    }

    /**
     * §5.8.1, as the browser writes it.
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
