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
 * OIDC Core §5.1: the claims providers the wiring gave this provider, answering as one. A deployment
 * that serves claims of its own wires a class beside the standard one, and nothing that enumerates
 * scopes or claims is edited.
 */
final class ServedClaimsTest extends TestCase
{
    /**
     * OIDC Core §5.1, §5.5: a user is described by every wired provider at once, and what each one
     * serves it serves alone.
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
     * OIDC Discovery §3: a scope of a deployment is announced because a class serves it, and a scope two
     * providers name is one scope of this provider.
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
     * OIDC Discovery §3: "claims_supported" is what the wired providers hold together, each claim named
     * once.
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
     * OIDC Core §5.4: a scope two providers serve stands for the claims each puts under it, each claim named
     * once.
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

    /**
     * A scope no wired provider serves stands for no claim, so nothing is asked for under it by name.
     */
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

    /**
     * Which of the two values a client would receive is not something a deployment should have to guess,
     * as it is not for a member of the discovery document.
     */
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

    /**
     * A deployment wired with no claims provider serves "sub" and nothing else, which is what the
     * document then says of it.
     */
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
