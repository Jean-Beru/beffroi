<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\ServiceProvider;

use ArgumentCountError;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProviderMetadata;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md section 5.2, S-9, S-11, S-19
 */
final class ServiceProviderMetadataTest extends TestCase
{
    /**
     * S-9, S-11
     */
    #[Test]
    public function aReadingCannotLeaveOutWhatDecidesTheSignatureOfARequest(): void
    {
        // Then
        $this->expectException(ArgumentCountError::class);
        $this->expectExceptionMessageIsOrContains('3 passed');

        // When
        new ServiceProviderMetadata('https://sp.example.com/saml', null, []); // @phpstan-ignore arguments.count, new.resultUnused (the contract is broken on purpose)
    }

    /**
     * S-6
     */
    #[Test]
    public function aReadingCannotLeaveOutWhetherItWasSigned(): void
    {
        // Then
        $this->expectException(ArgumentCountError::class);
        $this->expectExceptionMessageIsOrContains('5 passed');

        // When
        new ServiceProviderMetadata('https://sp.example.com/saml', null, [], false, []); // @phpstan-ignore arguments.count, new.resultUnused (the contract is broken on purpose)
    }

    /**
     * S-19
     *
     * @param list<Certificate> $certificates
     */
    #[Test]
    #[DataProvider('provideEncryptionCertificates')]
    public function itEncryptsForTheFirstCertificateForEncryption(array $certificates, ?Certificate $expected): void
    {
        // Given
        $metadata = new ServiceProviderMetadata(ServiceProviderDocuments::SIGNED, null, $certificates, false, [], readSigned: false);

        // When / Then
        static::assertEquals($expected, $metadata->encryptionCertificate());
    }

    /**
     * @return iterable<string, array{list<Certificate>, ?Certificate}>
     */
    public static function provideEncryptionCertificates(): iterable
    {
        yield 'none' => [[], null];
        yield 'one' => [[ServiceProviderDocuments::signer('sp')], ServiceProviderDocuments::signer('sp')];
        yield 'two, during a rotation of the service provider' => [
            [ServiceProviderDocuments::signer('idp'), ServiceProviderDocuments::signer('sp')],
            ServiceProviderDocuments::signer('idp'),
        ];
    }
}
