<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function base64_encode;
use function is_string;
use LogicException;
use const OPENSSL_KEYTYPE_EC;
use function openssl_pkey_export;
use function openssl_pkey_new;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\UnknownExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;

/**
 * A certificate authority that attests authenticators, as a maker or an organisation does: WebAuthn Level 3 §8.2.1, §8.2.2
 */
final readonly class AttestationAuthority
{
    /**
     * WebAuthn Level 3 §8.2.2, id-fido-gen-ce-sernum
     */
    private const string SERIAL_NUMBER = '1.3.6.1.4.1.45724.1.1.2';

    private function __construct(
        private Certificate $root,
        private PrivateKey $rootKey,
    ) {
    }

    public static function create(string $name = 'Attestation Authority of the tests'): self
    {
        $key = self::key();
        $subject = Name::fromString('cn=' . $name);
        $root = TBSCertificate::create($subject, $key->publicKey()->publicKeyInfo(), $subject, self::validity())
            ->withRandomSerialNumber()
            ->withAdditionalExtensions(BasicConstraintsExtension::create(true, true), KeyUsageExtension::create(true, KeyUsageExtension::KEY_CERT_SIGN))
            ->sign(ECDSAWithSHA256AlgorithmIdentifier::create(), $key->privateKeyInfo());

        return new self($root, $key);
    }

    public function rootCertificate(): string
    {
        return $this->root->toPEM()->string();
    }

    /**
     * FIDO Metadata Statement v3.1.1 §4.1, attestationRootCertificates: DER in base64
     */
    public function rootInMetadata(): string
    {
        return base64_encode($this->root->toDER());
    }

    /**
     * @param string|null $serialNumber the octets of id-fido-gen-ce-sernum
     * @param Element|null $serialNumberValue another value than the OCTET STRING of the serial number
     */
    public function attest(?string $serialNumber = null, bool $serialNumberIsCritical = false, ?Element $serialNumberValue = null): AttestationCertificate
    {
        $key = self::key();
        $extensions = [BasicConstraintsExtension::create(true, false)];
        if ($serialNumber !== null || $serialNumberValue !== null) {
            $extensions[] = UnknownExtension::create(
                self::SERIAL_NUMBER,
                $serialNumberIsCritical,
                $serialNumberValue ?? OctetString::create((string) $serialNumber),
            );
        }
        $certificate = TBSCertificate::create(
            Name::fromString('cn=Authenticator of the tests,ou=Authenticator Attestation,o=Beffroi,c=FR'),
            $key->publicKey()->publicKeyInfo(),
            $this->root->tbsCertificate()->subject(),
            self::validity(),
        )
            ->withRandomSerialNumber()
            ->withIssuerCertificate($this->root)
            ->withAdditionalExtensions(...$extensions)
            ->sign(ECDSAWithSHA256AlgorithmIdentifier::create(), $this->rootKey->privateKeyInfo());

        return new AttestationCertificate($key->toPEM()->string(), $certificate->toDER(), $certificate->toPEM()->string());
    }

    private static function validity(): Validity
    {
        return Validity::fromStrings('2026-01-01T00:00:00Z', '2046-01-01T00:00:00Z');
    }

    private static function key(): PrivateKey
    {
        $key = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        if ($key === false || ! openssl_pkey_export($key, $pem) || ! is_string($pem)) {
            throw new LogicException('OpenSSL could not generate a P-256 key.');
        }

        return PrivateKey::fromPEM(PEM::fromString($pem));
    }
}
