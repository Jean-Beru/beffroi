<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Claims;

use function array_map;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Claims\ServedClaims;
use Beffroi\Oidc\Application\Claims\StandardClaimsProvider;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\FakeClaimsProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §5.1
 */
final class ServedClaimsTest extends TestCase
{
    /**
     * OIDC Core §5.1, §5.5
     */
    #[Test]
    public function itServesTheClaimsOfEveryWiredProvider(): void
    {
        // Given
        $served = new ServedClaims([
            FakeClaimsProvider::of(['profile'], ['nickname'], ['nickname' => 'ali']),
            FakeClaimsProvider::of(['billing'], ['billing_id'], ['billing_id' => 'AC-4711']),
        ]);

        // When
        $claims = $served->claims(Fixtures::user(), self::scopes(['profile', 'billing']), []);

        // Then
        static::assertSame(
            [
                'nickname' => 'ali',
                'billing_id' => 'AC-4711',
            ],
            $claims,
        );
    }

    /**
     * OIDC Discovery §3
     */
    #[Test]
    public function itServesTheScopesOfEveryWiredProviderEachOnce(): void
    {
        // Given
        $served = new ServedClaims([
            new StandardClaimsProvider(),
            FakeClaimsProvider::of(['profile', 'billing'], ['billing_id']),
        ]);

        // When
        $scopes = $served->supportedScopes();

        // Then
        static::assertSame(
            ['profile', 'email', 'address', 'phone', 'billing'],
            array_map(static fn (Scope $scope): string => $scope->value, $scopes),
        );
    }

    /**
     * OIDC Discovery §3
     */
    #[Test]
    public function itServesTheClaimsNamesOfEveryWiredProviderEachOnce(): void
    {
        // Given
        $served = new ServedClaims([
            FakeClaimsProvider::of(['billing'], ['billing_id', 'billing_id']),
            FakeClaimsProvider::of(['shipping'], ['shipping_id']),
        ]);

        // When
        $claims = $served->supportedClaims();

        // Then
        static::assertSame(['billing_id', 'shipping_id'], $claims);
    }

    /**
     * OIDC Core §5.4
     */
    #[Test]
    public function aScopeStandsForTheClaimsEveryWiredProviderPutsUnderIt(): void
    {
        // Given
        $served = new ServedClaims([
            new StandardClaimsProvider(),
            FakeClaimsProvider::of(['email', 'billing'], ['billing_id', 'email']),
        ]);

        // When
        $claims = $served->claimsOf(self::scopes(['email']));

        // Then
        static::assertSame(['email', 'email_verified', 'billing_id'], $claims);
    }

    #[Test]
    public function aScopeNoWiredProviderServesStandsForNoClaim(): void
    {
        // Given
        $served = new ServedClaims([
            new StandardClaimsProvider(),
            FakeClaimsProvider::of(['billing'], ['billing_id']),
        ]);

        // When
        $claims = $served->claimsOf(self::scopes(['openid', 'invoices.read']));

        // Then
        static::assertSame([], $claims);
    }

    #[Test]
    public function itRefusesTwoProvidersThatServeTheSameClaim(): void
    {
        // Given
        $served = new ServedClaims([
            FakeClaimsProvider::of(['profile'], ['nickname'], ['nickname' => 'ali']),
            FakeClaimsProvider::of(['profile'], ['nickname'], ['nickname' => 'alice']),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Two claims providers of this provider both serve "nickname".');

        // When
        $served->claims(Fixtures::user(), self::scopes(['profile']), []);
    }

    #[Test]
    public function aProviderWiredWithNoneServesNothing(): void
    {
        // Given
        $served = new ServedClaims([]);

        // When
        $claims = $served->supportedClaims();

        // Then
        static::assertSame([], $claims);
    }

    /**
     * @param list<string> $scopes
     */
    private static function scopes(array $scopes): Scopes
    {
        return new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes));
    }
}
