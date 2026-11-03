<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\AuthorizationDetails\ServedAuthorizationDetailTypes;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetail;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetailTypeInterface;
use function json_encode;
use const JSON_THROW_ON_ERROR;

/**
 * The authorization details the tests speak of (RFC 9396 §2), and the wirings they read them from. The
 * provider wires no type, no type of detail being universal, so every test that reads one wires the invented
 * type of InventedAuthorizationDetailType, which is exactly what a deployment does.
 */
final readonly class AuthorizationDetailTypes
{
    /**
     * A type a deployment serves.
     */
    public const string INVENTED = InventedAuthorizationDetailType::TYPE;

    /**
     * A type nobody wired, which every request naming it is refused for.
     */
    public const string UNSERVED = 'payment_initiation';

    /**
     * @param list<AuthorizationDetailTypeInterface>|null $types the invented one unless the test says otherwise
     */
    public static function served(?array $types = null): ServedAuthorizationDetailTypes
    {
        return new ServedAuthorizationDetailTypes($types ?? [new InventedAuthorizationDetailType()]);
    }

    /**
     * A provider wired with no type at all, which is what the provider ships.
     */
    public static function none(): ServedAuthorizationDetailTypes
    {
        return new ServedAuthorizationDetailTypes([]);
    }

    /**
     * One detail of the invented type, as that type keeps it.
     *
     * @param list<string> $actions
     */
    public static function detail(string $account = 'acct-4711', array $actions = ['read']): AuthorizationDetail
    {
        return new InventedAuthorizationDetailType()->of([
            InventedAuthorizationDetailType::ACCOUNT => $account,
            InventedAuthorizationDetailType::ACTIONS => $actions,
        ]);
    }

    /**
     * A set holding that one detail.
     *
     * @param list<string> $actions
     */
    public static function details(string $account = 'acct-4711', array $actions = ['read']): AuthorizationDetails
    {
        return new AuthorizationDetails([self::detail($account, $actions)]);
    }

    /**
     * The "authorization_details" parameter of a request asking for that detail, as it travels on the wire.
     *
     * @param list<string> $actions
     */
    public static function parameter(string $account = 'acct-4711', array $actions = ['read'], string $type = self::INVENTED): string
    {
        return json_encode([
            [
                AuthorizationDetail::TYPE => $type,
                InventedAuthorizationDetailType::ACCOUNT => $account,
                InventedAuthorizationDetailType::ACTIONS => $actions,
            ],
        ], JSON_THROW_ON_ERROR);
    }
}
