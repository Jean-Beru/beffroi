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

/**
 * The scopes a deployment declares for the tenant it declares (issue #920), read when the list is built: a deployment
 * that declares a value the tenant cannot hand out is told so there, and by no registration.
 */
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

    /**
     * What one tenant hands out is no business of another: asked about a tenant this deployment does not declare,
     * the list answers as a tenant that declares none.
     */
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
     * RFC 6749 §3.3: the scopes of a tenant are a set, so a scope declared twice is declared once, where it was
     * first named.
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
     * RFC 6749 §3.3: a scope token is one or more of the printable characters of ASCII but the space, the double
     * quote and the backslash, and nothing after it.
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
     * OIDC Core §11: "offline_access" asks for a refresh token, which the wired grants make good or do not. A
     * deployment that declares it is told so when the list is built, rather than having the provider announce what
     * its token endpoint may not issue.
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
     * The scopes of the tenant of the fixtures, as a deployment declares them.
     *
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
