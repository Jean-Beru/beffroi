<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Beffroi\Xml\Dsig\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Tests\Dsig\Support\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * Section 5.2, D-15, D-16
 */
final class PrivateKeyTest extends TestCase
{
    /**
     * §9.3 row 10
     */
    #[Test]
    #[DataProvider('providePkcs1Schemes')]
    public function itSignsDeterministicallyWithAPkcs1Scheme(SignatureAlgorithm $algorithm): void
    {
        // Given
        $key = PrivateKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));

        // When
        $signature = $key->sign('canonical SignedInfo', $algorithm);

        // Then
        static::assertSame(256, strlen($signature));
        static::assertSame($signature, $key->sign('canonical SignedInfo', $algorithm));
    }

    /**
     * @return iterable<string, array{SignatureAlgorithm}>
     */
    public static function providePkcs1Schemes(): iterable
    {
        yield 'rsa-sha256' => [SignatureAlgorithm::RsaSha256];
        yield 'rsa-sha384' => [SignatureAlgorithm::RsaSha384];
        yield 'rsa-sha512' => [SignatureAlgorithm::RsaSha512];
    }

    /**
     * §9.3 row 10, section 13
     */
    #[Test]
    public function itSignsWithARandomSaltUnderPss(): void
    {
        // Given
        if (! SignatureAlgorithm::RsaPssSha256->isAvailable()) {
            static::markTestSkipped('RSASSA-PSS is unavailable on this build; the refusal has its own test.');
        }
        $key = PrivateKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));

        // When
        $first = $key->sign('canonical SignedInfo', SignatureAlgorithm::RsaPssSha256);
        $second = $key->sign('canonical SignedInfo', SignatureAlgorithm::RsaPssSha256);

        // Then
        static::assertSame(256, strlen($first));
        static::assertNotSame($first, $second);
    }

    /**
     * §9.1, section 13
     */
    #[Test]
    public function itRefusesPssWhereTheBuildCannotProduceIt(): void
    {
        // Given
        if (SignatureAlgorithm::RsaPssSha256->isAvailable()) {
            static::markTestSkipped('RSASSA-PSS is available on this build; the refusal is the business of PHP 8.4 and of OpenSSL before 3.1.');
        }
        $key = PrivateKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));

        // Then
        $this->expectException(AlgorithmUnavailable::class);
        $this->expectExceptionMessageIs('This build cannot produce RSASSA-PSS: it needs PHP 8.5 and OpenSSL 3.1 (section 13).');

        // When
        $key->sign('canonical SignedInfo', SignatureAlgorithm::RsaPssSha256);
    }

    /**
     * Section 5.2
     */
    #[Test]
    public function itReadsAnEncryptedPemWithItsPassphrase(): void
    {
        // Given
        $pem = Fixtures::bytes('keys/encrypted-rsa-2048-key.pem');

        // When
        $key = PrivateKey::fromPem($pem, 'test-passphrase');

        // Then
        static::assertSame(256, strlen($key->sign('bytes', SignatureAlgorithm::RsaSha256)));
    }

    /**
     * D-16
     */
    #[Test]
    #[TestWith(['keys/encrypted-rsa-2048-key.pem', 'wrong'], 'a wrong passphrase')]
    #[TestWith(['keys/encrypted-rsa-2048-key.pem', null], 'no passphrase')]
    #[TestWith(['keys/test-signing-certificate.pem', null], 'a certificate, which holds no private key')]
    public function itRefusesAPemThatGivesNoPrivateKey(string $file, ?string $passphrase): void
    {
        // Given
        $pem = Fixtures::bytes($file);

        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('The PEM holds no private key, or the passphrase is wrong (D-16).');

        // When
        PrivateKey::fromPem($pem, $passphrase);
    }

    /**
     * Section 5.2
     */
    #[Test]
    public function itRefusesAPathToAKeyFile(): void
    {
        // Given
        $path = 'file://' . Fixtures::path('keys/test-signing-key.pem');

        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('The PEM holds no private key, or the passphrase is wrong (D-16).');

        // When
        PrivateKey::fromPem($path);
    }

    /**
     * §9.2 row 36, D-16
     */
    #[Test]
    #[TestWith(['keys/weak-rsa-1024-key.pem'], 'RSA-1024')]
    #[TestWith(['keys/dsa-2048-key.pem'], 'DSA-2048')]
    #[TestWith(['keys/ec-p256-key.pem'], 'EC P-256')]
    public function itRefusesAWeakOrNonRsaKey(string $file): void
    {
        // Given
        $pem = Fixtures::bytes($file);

        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('A signing key is RSA of at least 2048 bits (D-16).');

        // When
        PrivateKey::fromPem($pem);
    }

    /**
     * D-13
     */
    #[Test]
    public function itsRefusalCarriesNothingOfThePem(): void
    {
        // When
        try {
            PrivateKey::fromPem("-----BEGIN PRIVATE KEY-----\nsecretlookingbase64==\n-----END PRIVATE KEY-----\n");
            static::fail('The PEM holds no key.');
        } catch (InvalidKey $refused) {
            // Then
            static::assertStringNotContainsString('secret', $refused->getMessage());
        }
    }
}
