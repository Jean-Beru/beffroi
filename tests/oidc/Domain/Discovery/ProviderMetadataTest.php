<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Discovery;

use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Oidc\Domain\Discovery\ProviderMetadata;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ProviderMetadataTest extends TestCase
{
    #[Test]
    public function itCarriesTheMembersItWasGivenInTheirOrder(): void
    {
        // Given
        $members = [
            'issuer' => 'https://id.acme.example',
            'response_types_supported' => ['code'],
            'claims_parameter_supported' => true,
        ];

        // When
        $document = new ProviderMetadata(new Issuer('https://id.acme.example'), $members, 3600)->toArray();

        // Then
        static::assertSame($members, $document);
    }

    #[Test]
    public function itIsPubliclyCacheableForItsLifetime(): void
    {
        // When
        $metadata = self::metadata(3600);

        // Then
        static::assertSame(
            [
                'Cache-Control' => 'public, max-age=3600',
            ],
            $metadata->headers,
        );
    }

    #[Test]
    public function aLifetimeOfZeroRevalidatesEveryTime(): void
    {
        // When
        $metadata = self::metadata(0);

        // Then
        static::assertSame(
            [
                'Cache-Control' => 'public, max-age=0',
            ],
            $metadata->headers,
        );
    }

    #[Test]
    public function aNegativeLifetimeIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('number of seconds');

        // When
        self::metadata(-1);
    }

    /**
     * OIDC Discovery §4.1, RFC 8414 §3
     */
    #[Test]
    public function theWellKnownLocationsOfAnIssuerWithoutPathCoincide(): void
    {
        // When
        $metadata = self::metadata();

        // Then
        static::assertSame('https://id.acme.example/.well-known/openid-configuration', $metadata->openIdConfigurationUrl());
        static::assertSame('https://id.acme.example/.well-known/oauth-authorization-server', $metadata->authorizationServerMetadataUrl());
    }

    #[Test]
    public function theWellKnownLocationsOfAnIssuerWithAPathDiffer(): void
    {
        // When
        $metadata = new ProviderMetadata(new Issuer('https://as.example:8443/tenants/acme'), [], 3600);

        // Then
        static::assertSame('https://as.example:8443/tenants/acme/.well-known/openid-configuration', $metadata->openIdConfigurationUrl());
        static::assertSame('https://as.example:8443/.well-known/oauth-authorization-server/tenants/acme', $metadata->authorizationServerMetadataUrl());
    }

    #[Test]
    public function theJsonIsTheDocument(): void
    {
        // Given
        $metadata = self::metadata();

        // When
        $decoded = json_decode($metadata->toJson(), true, 4, JSON_THROW_ON_ERROR);

        // Then
        static::assertSame($metadata->toArray(), $decoded);
    }

    /**
     * OIDC Discovery §4.3
     */
    #[Test]
    #[DataProvider('provideWhatTheJsonCarriesAsItIs')]
    public function theJsonCarriesEachKindOfValueAsItIs(string $fragment): void
    {
        // When
        $json = self::metadata()->toJson();

        // Then
        static::assertStringContainsString($fragment, $json);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatTheJsonCarriesAsItIs(): iterable
    {
        yield 'the issuer byte for byte' => ['"issuer":"https://id.acme.example"'];
        yield 'a boolean as a JSON boolean' => ['"authorization_response_iss_parameter_supported":true'];
        yield 'a list as a JSON array' => ['"response_types_supported":["code"]'];
    }

    private static function metadata(int $maxAge = 3600): ProviderMetadata
    {
        return new ProviderMetadata(
            new Issuer('https://id.acme.example'),
            [
                'issuer' => 'https://id.acme.example',
                'response_types_supported' => ['code'],
                'authorization_response_iss_parameter_supported' => true,
            ],
            $maxAge,
        );
    }
}
