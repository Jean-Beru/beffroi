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
 * RFC 9396 §2
 */
final readonly class AuthorizationDetailTypes
{
    public const string INVENTED = InventedAuthorizationDetailType::TYPE;

    public const string UNSERVED = 'payment_initiation';

    /**
     * @param list<AuthorizationDetailTypeInterface>|null $types
     */
    public static function served(?array $types = null): ServedAuthorizationDetailTypes
    {
        return new ServedAuthorizationDetailTypes($types ?? [new InventedAuthorizationDetailType()]);
    }

    public static function none(): ServedAuthorizationDetailTypes
    {
        return new ServedAuthorizationDetailTypes([]);
    }

    /**
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
     * @param list<string> $actions
     */
    public static function details(string $account = 'acct-4711', array $actions = ['read']): AuthorizationDetails
    {
        return new AuthorizationDetails([self::detail($account, $actions)]);
    }

    /**
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
