<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\JwtLibrary;

use Beffroi\Core\Bridge\JwtLibrary\Algorithm\A256Gcm;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\EcdhEsA256Kw;
use Beffroi\Core\Bridge\JwtLibrary\JoseContentEncryptionAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseEncryptionAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseKeyEncryptionAlgorithms;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\UnsupportedAlgorithmException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The two registries a JWE is made and opened with, filled by the wiring and read by the document, by the
 * registrations of the clients and by the decrypter alike.
 */
final class EncryptionAlgorithmsTest extends TestCase
{
    #[Test]
    public function itFindsAContentEncryptionByItsName(): void
    {
        // When / Then
        static::assertSame(Algorithms::a256Gcm(), Algorithms::contentEncryption()->named('A256GCM'));
    }

    /**
     * A name nothing is wired with is refused, and the refusal says what is wired, because a registration
     * is read at boot and an operator has to know what to write instead.
     */
    #[Test]
    public function aContentEncryptionNothingIsWiredWithIsRefusedWithTheWiredOnes(): void
    {
        // Then
        $this->expectException(UnsupportedAlgorithmException::class);
        $this->expectExceptionMessageIs('This provider does not encrypt a payload with "A128CBC-HS256"; it encrypts with A256GCM.');

        // When
        Algorithms::contentEncryption()->named('A128CBC-HS256');
    }

    /**
     * A deployment that encrypts nothing says that, rather than listing nothing.
     */
    #[Test]
    public function aProviderThatEncryptsNoPayloadSaysSo(): void
    {
        // Then
        $this->expectException(UnsupportedAlgorithmException::class);
        $this->expectExceptionMessageIs('This provider encrypts no payload; "A256GCM" is not read.');

        // When
        new JoseContentEncryptionAlgorithms([])->named('A256GCM');
    }

    #[Test]
    public function aContentEncryptionWiredTwiceIsRefusedAtBoot(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The algorithm "A256GCM" is wired twice.');

        // When
        new JoseContentEncryptionAlgorithms([new A256Gcm(), new A256Gcm()]);
    }

    /**
     * The manager a builder and a reader of JWE are given holds both lists, so the provider cannot mint
     * what it could not open.
     */
    #[Test]
    public function theManagerHoldsTheKeyManagementAndTheContentEncryptionAlgorithms(): void
    {
        // Given
        $algorithms = new JoseEncryptionAlgorithms(new JoseKeyEncryptionAlgorithms([new EcdhEsA256Kw()]), new JoseContentEncryptionAlgorithms([new A256Gcm()]));

        // When
        $manager = $algorithms->manager();

        // Then
        static::assertSame(['ECDH-ES+A256KW', 'A256GCM'], $manager->list());
    }
}
