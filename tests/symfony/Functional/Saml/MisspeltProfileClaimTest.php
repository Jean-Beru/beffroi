<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Saml;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Filesystem\Filesystem;

/**
 * beffroi/saml, spec/saml.md S-45, section 6.10 step 1
 */
final class MisspeltProfileClaimTest extends KernelTestCase
{
    private const string MISSPELT_CLAIM = 'test_misspelt_claim';

    /**
     * S-45, section 6.10 step 1
     */
    #[Test]
    public function theBootThatCompilesTheContainerFails(): void
    {
        // Given
        $kernel = self::createKernel([
            'environment' => self::MISSPELT_CLAIM,
        ]);
        // A container left by a previous run is read back without the warmer: this boot compiles its own.
        new Filesystem()->remove($kernel->getBuildDir());

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('Invalid configuration for path "beffroi.saml.identity_providers": The identity provider "https://idp.example.org/saml": '
        . 'the attribute "givenName" fills the claim "givenName", which the profile of a person does not hold in this deployment (spec/saml.md S-45).');

        // When
        $kernel->boot();
    }
}
