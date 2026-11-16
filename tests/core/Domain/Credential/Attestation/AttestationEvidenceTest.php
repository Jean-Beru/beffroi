<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential\Attestation;

use Beffroi\Core\Domain\Credential\Attestation\AttestationEvidence;
use Beffroi\Core\Domain\Credential\Attestation\ModelProof;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * WebAuthn Level 3 §8.2.2
 */
final class AttestationEvidenceTest extends TestCase
{
    #[Test]
    public function anEnterpriseAttestationKeepsTheSerialNumberOfItsAuthenticator(): void
    {
        // When / Then
        static::assertSame('0a1b', AttestationEvidence::enterprise('0a1b')->serialNumber);
    }

    #[Test]
    #[DataProvider('provideModelsProvedWithoutAnEnterpriseAttestation')]
    public function onlyAnEnterpriseAttestationCarriesASerialNumber(ModelProof $model): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Only an enterprise attestation carries the serial number of its authenticator (WebAuthn Level 3 §8.2.2).');

        // When
        new AttestationEvidence($model, '0a1b');
    }

    /**
     * @return iterable<string, array{ModelProof}>
     */
    public static function provideModelsProvedWithoutAnEnterpriseAttestation(): iterable
    {
        yield 'declared' => [ModelProof::Declared];
        yield 'verified' => [ModelProof::Verified];
    }

    #[Test]
    #[DataProvider('provideWhatIsNoOctetStringInHexadecimal')]
    public function aSerialNumberIsAnOctetStringInLowercaseHexadecimal(string $serialNumber): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The serial number of an authenticator is an octet string, written in lowercase hexadecimal.');

        // When
        AttestationEvidence::enterprise($serialNumber);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNoOctetStringInHexadecimal(): iterable
    {
        yield 'nothing' => [''];
        yield 'an odd number of digits' => ['0a1'];
        yield 'uppercase' => ['0A1B'];
        yield 'not hexadecimal' => ['zz'];
    }
}
