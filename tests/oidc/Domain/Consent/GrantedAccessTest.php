<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Consent;

use function array_map;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Consent\GrantedAccess;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 6749 §3.3, OIDC Core §5.5, RFC 9396 §2
 */
final class GrantedAccessTest extends TestCase
{
    #[Test]
    public function everyScopeIsNamedOnceInTheOrderOfTheirValues(): void
    {
        // When
        $access = GrantedAccess::of([self::consent(['openid', 'profile']), self::consent(['openid', 'email'])]);

        // Then
        static::assertSame(['email', 'openid', 'profile'], array_map(static fn (Scope $scope): string => $scope->value, $access->scopes));
    }

    #[Test]
    public function everyClaimIsNamedOnceInTheOrderOfTheirNames(): void
    {
        // When
        $access = GrantedAccess::of([self::consent(['openid'], ['nickname', 'email']), self::consent(['openid'], ['email'])]);

        // Then
        static::assertSame(['email', 'nickname'], $access->claims);
    }

    #[Test]
    public function everyTypeOfDetailsIsNamedOnce(): void
    {
        // When
        $access = GrantedAccess::of([self::consent(['openid'], details: true), self::consent(['openid'], details: true), self::consent(['openid'])]);

        // Then
        static::assertSame([AuthorizationDetailTypes::INVENTED], $access->types);
    }

    /**
     * @param list<string> $scopes
     * @param list<string> $claims
     */
    private static function consent(array $scopes, array $claims = [], bool $details = false): Consent
    {
        $user = Fixtures::user();

        return new Consent(
            Uuid::v7(),
            $user,
            Clients::public($user->tenant),
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            Fixtures::now(),
            $details ? AuthorizationDetailTypes::details() : null,
            new ClaimNames($claims),
        );
    }
}
