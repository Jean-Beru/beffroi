<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Bridge\Configuration;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationAdministrationResource;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0038: the administration API a deployment names for the tenant it declares, by its resource identifier
 * (RFC 8707 §2).
 */
final class ConfigurationAdministrationResourceTest extends TestCase
{
    #[Test]
    public function theApiIsTheOneOfTheTenantTheDeploymentDeclares(): void
    {
        // Given
        $resource = new ConfigurationAdministrationResource('acme', 'https://admin.acme.example');

        // When
        $administration = $resource->administrationResourceOf(Fixtures::tenant('acme'));

        // Then
        static::assertSame('https://admin.acme.example', $administration?->value);
    }

    #[Test]
    public function anotherTenantHasNone(): void
    {
        // Given
        $resource = new ConfigurationAdministrationResource('acme', 'https://admin.acme.example');

        // When
        $administration = $resource->administrationResourceOf(Fixtures::tenant('globex'));

        // Then
        static::assertNull($administration);
    }

    #[Test]
    public function aDeploymentThatNamesNoneHasNone(): void
    {
        // Given
        $resource = new ConfigurationAdministrationResource('acme');

        // When
        $administration = $resource->administrationResourceOf(Fixtures::tenant('acme'));

        // Then
        static::assertNull($administration);
    }

    #[Test]
    #[DataProvider('provideIdentifiersNoResourceCarries')]
    public function anIdentifierNoResourceCarriesRefusesTheConstruction(string $identifier): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('The administration API of the tenant "acme" is named by an identifier that is no resource identifier');

        // When
        new ConfigurationAdministrationResource('acme', $identifier);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideIdentifiersNoResourceCarries(): iterable
    {
        yield 'a path alone' => ['/administration'];
        yield 'a fragment' => ['https://admin.acme.example/#api'];
        yield 'an empty identifier' => [''];
    }
}
