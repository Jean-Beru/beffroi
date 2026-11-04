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

final class EncryptionAlgorithmsTest extends TestCase
{
    #[Test]
    public function itFindsAContentEncryptionByItsName(): void
    {
        // When / Then
        static::assertSame(Algorithms::a256Gcm(), Algorithms::contentEncryption()->named('A256GCM'));
    }

    #[Test]
    public function aContentEncryptionNothingIsWiredWithIsRefusedWithTheWiredOnes(): void
    {
        // Then
        $this->expectException(UnsupportedAlgorithmException::class);
        $this->expectExceptionMessageIs('This provider does not encrypt a payload with "A128CBC-HS256"; it encrypts with A256GCM.');

        // When
        Algorithms::contentEncryption()->named('A128CBC-HS256');
    }

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
