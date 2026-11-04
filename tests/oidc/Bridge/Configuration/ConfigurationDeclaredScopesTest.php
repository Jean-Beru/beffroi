<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Bridge\Configuration;

use function array_map;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationDeclaredScopes;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

final class ConfigurationDeclaredScopesTest extends TestCase
{
    #[Test]
    public function theTenantIsDeclaredTheScopesTheDeploymentNames(): void
    {
        // Given
        $declared = self::declared(['invoices.read', 'invoices.pay']);

        // When
        $scopes = self::values($declared, Fixtures::tenant());

        // Then
        static::assertSame(['invoices.read', 'invoices.pay'], $scopes);
    }

    #[Test]
    public function anotherTenantIsDeclaredNone(): void
    {
        // Given
        $declared = self::declared(['invoices.read']);

        // When
        $scopes = self::values($declared, Fixtures::tenant('other', 'https://id.other.example'));

        // Then
        static::assertSame([], $scopes);
    }

    /**
     * RFC 6749 §3.3
     */
    #[Test]
    public function aScopeDeclaredTwiceIsDeclaredOnce(): void
    {
        // Given
        $declared = self::declared(['invoices.read', 'invoices.pay', 'invoices.read']);

        // When
        $scopes = self::values($declared, Fixtures::tenant());

        // Then
        static::assertSame(['invoices.read', 'invoices.pay'], $scopes);
    }

    #[Test]
    #[DataProvider('provideValuesThatAreNoScopeToken')]
    public function aValueThatIsNoScopeTokenIsRefusedWhenTheListIsBuilt(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The scope "%s" is declared for the tenant "acme", and it is not a scope token (RFC 6749 §3.3).',
            $value,
        ));

        // When
        self::declared(['invoices.read', $value]);
    }

    /**
     * RFC 6749 §3.3
     *
     * @return iterable<string, array{string}>
     */
    public static function provideValuesThatAreNoScopeToken(): iterable
    {
        yield 'an empty string' => [''];
        yield 'two tokens in one value' => ['invoices.read invoices.pay'];
        yield 'a double quote' => ['invoices"read'];
        yield 'a backslash' => ['invoices\read'];
        yield 'a line feed after the token' => ["invoices.read\n"];
    }

    /**
     * OIDC Core §11
     */
    #[Test]
    public function offlineAccessIsRefusedWhenTheListIsBuilt(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The scope "offline_access" is declared for the tenant "acme": it asks for a refresh token (OIDC Core §11), which the tenant offers where the wired grants issue and spend one, and never because it is declared.');

        // When
        self::declared(['invoices.read', 'offline_access']);
    }

    /**
     * @param list<string> $scopes
     */
    private static function declared(array $scopes): ConfigurationDeclaredScopes
    {
        return new ConfigurationDeclaredScopes('acme', $scopes);
    }

    /**
     * @return list<string>
     */
    private static function values(ConfigurationDeclaredScopes $declared, Tenant $tenant): array
    {
        return array_map(static fn (Scope $scope): string => $scope->value, $declared->scopesDeclaredFor($tenant));
    }
}
