<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function base64_encode;
use function is_string;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use LogicException;
use const OPENSSL_KEYTYPE_EC;
use function openssl_pkey_export;
use function openssl_pkey_new;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;

/**
 * FIDO Metadata Service v3.1.1 §3.1.7, RFC 7515 §4.1.6
 */
final readonly class MetadataSigner
{
    private function __construct(
        private Certificate $root,
        private PrivateKey $rootKey,
        private Certificate $intermediate,
        private Certificate $signer,
        private PrivateKey $signerKey,
    ) {
    }

    public static function create(string $name = 'Test Metadata Service'): self
    {
        $validity = self::validity();
        $rootKey = self::key();
        $rootName = Name::fromString('cn=' . $name . ' Root');
        $root = TBSCertificate::create($rootName, $rootKey->publicKey()->publicKeyInfo(), $rootName, $validity)
            ->withRandomSerialNumber()
            ->withAdditionalExtensions(BasicConstraintsExtension::create(true, true), KeyUsageExtension::create(true, KeyUsageExtension::KEY_CERT_SIGN))
            ->sign(ECDSAWithSHA256AlgorithmIdentifier::create(), $rootKey->privateKeyInfo());
        $intermediateKey = self::key();
        $intermediateName = Name::fromString('cn=' . $name . ' Intermediate');
        $intermediate = TBSCertificate::create($intermediateName, $intermediateKey->publicKey()->publicKeyInfo(), $rootName, $validity)
            ->withRandomSerialNumber()
            ->withIssuerCertificate($root)
            ->withAdditionalExtensions(BasicConstraintsExtension::create(true, true, 0), KeyUsageExtension::create(true, KeyUsageExtension::KEY_CERT_SIGN))
            ->sign(ECDSAWithSHA256AlgorithmIdentifier::create(), $rootKey->privateKeyInfo());
        $signerKey = self::key();
        $signer = TBSCertificate::create(Name::fromString('cn=' . $name . ' Signer'), $signerKey->publicKey()->publicKeyInfo(), $intermediateName, $validity)
            ->withRandomSerialNumber()
            ->withIssuerCertificate($intermediate)
            ->withAdditionalExtensions(KeyUsageExtension::create(true, KeyUsageExtension::DIGITAL_SIGNATURE))
            ->sign(ECDSAWithSHA256AlgorithmIdentifier::create(), $intermediateKey->privateKeyInfo());

        return new self($root, $rootKey, $intermediate, $signer, $signerKey);
    }

    public function rootCertificate(): string
    {
        return $this->root->toPEM()->string();
    }

    public function rootCertificateInDer(): string
    {
        return $this->root->toDER();
    }

    /**
     * @param list<mixed>|null $chain
     */
    public function sign(string $payload, ?array $chain = null): string
    {
        $jws = new JWSBuilder(new AlgorithmManager([new ES256()]))
            ->create()
            ->withPayload($payload)
            ->addSignature(JWKFactory::createFromKey($this->signerKey->toPEM()->string()), [
                'alg' => 'ES256',
                'x5c' => $chain ?? $this->chain(),
            ])
            ->build();

        return new CompactSerializer()->serialize($jws, 0);
    }

    /**
     * RFC 7515 §4.1.6
     *
     * @return list<string>
     */
    public function chain(): array
    {
        return [base64_encode($this->signer->toDER()), base64_encode($this->intermediate->toDER())];
    }

    public function rootIssuedBy(self $other): string
    {
        return $other->issue($this->root->tbsCertificate()->subject(), $this->rootKey->publicKey()->publicKeyInfo());
    }

    private function issue(Name $subject, PublicKeyInfo $key): string
    {
        $certificate = TBSCertificate::create($subject, $key, $this->root->tbsCertificate()->subject(), self::validity())
            ->withRandomSerialNumber()
            ->withIssuerCertificate($this->root)
            ->withAdditionalExtensions(BasicConstraintsExtension::create(true, true), KeyUsageExtension::create(true, KeyUsageExtension::KEY_CERT_SIGN))
            ->sign(ECDSAWithSHA256AlgorithmIdentifier::create(), $this->rootKey->privateKeyInfo());

        return base64_encode($certificate->toDER());
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
