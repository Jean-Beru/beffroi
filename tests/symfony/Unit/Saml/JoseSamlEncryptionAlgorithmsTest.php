<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Saml;

use App\Saml\JoseSamlEncryptionAlgorithms;
use App\Saml\SamlEncryption;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\RsaKeyBits;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-64
 */
final class JoseSamlEncryptionAlgorithmsTest extends TestCase
{
    /**
     * S-64
     */
    #[Test]
    public function theAlgorithmOfAProviderIsFoundByItsName(): void
    {
        // Given
        $algorithm = new SamlEncryption('https://idp-a.example/metadata');
        $registry = new JoseSamlEncryptionAlgorithms([new SamlEncryption('https://idp-b.example/metadata'), $algorithm]);

        // When / Then
        static::assertSame($algorithm, $registry->find('SAML-ENCRYPTION:https://idp-a.example/metadata'));
    }

    /**
     * S-64
     */
    #[Test]
    public function theNameOfAProviderNothingWiresIsRefused(): void
    {
        // Given
        $registry = new JoseSamlEncryptionAlgorithms([new SamlEncryption('https://idp-a.example/metadata')]);

        // When / Then
        static::assertSame(
            [
                null,
                'No SAML identity provider encrypts for a key named "SAML-ENCRYPTION:https://idp-c.example/metadata"; those that do encrypt for SAML-ENCRYPTION:https://idp-a.example/metadata.',
            ],
            [
                $registry->find('SAML-ENCRYPTION:https://idp-c.example/metadata'),
                $registry->refusalOf('SAML-ENCRYPTION:https://idp-c.example/metadata')->getMessage(),
            ],
        );
    }

    /**
     * S-64
     */
    #[Test]
    public function aDeploymentThatDeclaresNoProviderWiresNone(): void
    {
        // Given
        $registry = new JoseSamlEncryptionAlgorithms([]);

        // When / Then
        static::assertSame(
            [[], 'No SAML identity provider encrypts for a key named "SAML-ENCRYPTION:https://idp-a.example/metadata"; none is declared.'],
            [$registry->all(), $registry->refusalOf('SAML-ENCRYPTION:https://idp-a.example/metadata')->getMessage()],
        );
    }

    /**
     * S-64
     */
    #[Test]
    public function theKeyOfAProviderIsAnRsaKeyForEncryption(): void
    {
        // Given
        $algorithm = new SamlEncryption('https://idp-a.example/metadata', new RsaKeyBits(2048));

        // When
        $key = $algorithm->generateKey();

        // Then
        static::assertSame(
            ['RSA', 'SAML-ENCRYPTION:https://idp-a.example/metadata', 'enc', 'https://idp-a.example/metadata'],
            [$key->get('kty'), $key->get('alg'), $key->get('use'), $algorithm->identityProvider()],
        );
    }
}
