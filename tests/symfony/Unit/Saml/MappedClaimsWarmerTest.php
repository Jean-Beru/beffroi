<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use Beffroi\Bundle\Saml\MappedClaimsWarmer;
use Beffroi\Saml\Port\ServedClaimsInterface;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Spec/saml.md S-16, section 6.2 step 1: the claim of each mapping of the declarations the compilation built, checked
 * against the claims the provider serves right after the compilation, in the same build.
 */
final class MappedClaimsWarmerTest extends TestCase
{
    private const string ENTITY_ID = 'https://sp.example.com/saml';

    private const string CACHE_DIRECTORY = '/var/cache/prod';

    /**
     * S-16, section 6.2 step 1: a mapping of a claim the provider does not serve fails the build, naming the key of the
     * configuration, the service provider, the attribute and the claim.
     */
    #[Test]
    public function aMappingOfAClaimTheProviderDoesNotServeFailsTheBuild(): void
    {
        // Given
        $warmer = new MappedClaimsWarmer(self::mapping('a_claim_no_provider_serves'), self::served(['sub', 'email']));

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('Invalid configuration for path "beffroi.saml.service_providers": The service provider "https://sp.example.com/saml": '
        . 'the attribute "urn:oid:0.9.2342.19200300.100.1.3" maps the claim "a_claim_no_provider_serves", which this '
        . 'provider does not serve (spec/saml.md S-16).');

        // When
        $warmer->warmUp(self::CACHE_DIRECTORY);
    }

    /**
     * S-16, section 6.2 step 1: a mapping of a claim the provider serves builds, and the warmer leaves nothing to
     * preload.
     */
    #[Test]
    public function aMappingOfAClaimTheProviderServesBuilds(): void
    {
        // Given
        $warmer = new MappedClaimsWarmer(self::mapping('email'), self::served(['sub', 'email']));

        // When / Then
        static::assertSame([], $warmer->warmUp(self::CACHE_DIRECTORY));
    }

    /**
     * Section 6.2 step 1: the warmer is not optional, the warmers a kernel runs right after it compiled its container
     * being those that are not.
     */
    #[Test]
    public function itIsNotOptional(): void
    {
        // Given
        $warmer = new MappedClaimsWarmer([], self::served([]));

        // When / Then
        static::assertFalse($warmer->isOptional());
    }

    /**
     * Section 6.2 step 1: a deployment that declares no service provider asks nothing of its claims providers.
     */
    #[Test]
    public function noDeclarationAsksNothingOfTheClaims(): void
    {
        // Given
        $claims = $this->createMock(ServedClaimsInterface::class);
        $claims->expects(static::never())->method('names');
        $warmer = new MappedClaimsWarmer([], $claims);

        // When
        $preloaded = $warmer->warmUp(self::CACHE_DIRECTORY);

        // Then
        static::assertSame([], $preloaded);
    }

    /**
     * A declaration that maps one attribute from that claim.
     *
     * @return array<string, array<string, mixed>>
     */
    private static function mapping(string $claim): array
    {
        return [
            self::ENTITY_ID => [
                'metadata' => '/srv/saml/sp-metadata.xml',
                'attributes' => [
                    'urn:oid:0.9.2342.19200300.100.1.3' => [
                        'claim' => $claim,
                    ],
                ],
            ],
        ];
    }

    /**
     * @param list<string> $names
     */
    private static function served(array $names): ServedClaimsInterface
    {
        $claims = static::createStub(ServedClaimsInterface::class);
        $claims->method('names')->willReturn($names);

        return $claims;
    }
}
