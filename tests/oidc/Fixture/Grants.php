<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Oidc\Application\Token\ServedGrants;
use Heidi\Oidc\Domain\Client\GrantTypeName;

/**
 * The grant names the tests speak of, and the wirings they read them from. The two names the provider
 * serves today are written here once, so that a test says which grant it is about and no test says what
 * the provider is wired with.
 */
final readonly class Grants
{
    public static function authorizationCode(): GrantTypeName
    {
        return new GrantTypeName('authorization_code');
    }

    public static function refreshToken(): GrantTypeName
    {
        return new GrantTypeName('refresh_token');
    }

    public static function clientCredentials(): GrantTypeName
    {
        return new GrantTypeName('client_credentials');
    }

    public static function deviceCode(): GrantTypeName
    {
        return new GrantTypeName('urn:ietf:params:oauth:grant-type:device_code');
    }

    /**
     * A grant nobody wrote a line of production code for, named by an absolute URI as an extension
     * grant is (RFC 6749 §4.5, RFC 6755).
     */
    public static function invented(): GrantTypeName
    {
        return new GrantTypeName('urn:example:params:oauth:grant-type:invented');
    }

    /**
     * What the provider is wired with today: a grant that issues refresh tokens and sends the user back to
     * the client, and a grant that spends them, neither of them doing anything.
     */
    public static function served(): ServedGrants
    {
        return new ServedGrants([
            new FakeRefreshTokenIssuingGrant(self::authorizationCode()),
            new FakeRefreshTokenSpendingGrant(self::refreshToken()),
        ]);
    }

    /**
     * The same wiring with a grant a client uses for itself beside them (RFC 6749 §4.4), for what a
     * registration of such a grant must carry and must not.
     */
    public static function servedWithClientCredentials(): ServedGrants
    {
        return new ServedGrants([
            new FakeRefreshTokenIssuingGrant(self::authorizationCode()),
            new FakeRefreshTokenSpendingGrant(self::refreshToken()),
            new FakeClientActingGrant(self::clientCredentials()),
        ]);
    }

    /**
     * The same wiring with a grant whose user is asked on another device beside them (RFC 8628 §3.3), for
     * the endpoint where such a flow starts.
     */
    public static function servedWithDeviceCode(): ServedGrants
    {
        return new ServedGrants([
            new FakeRefreshTokenIssuingGrant(self::authorizationCode()),
            new FakeRefreshTokenSpendingGrant(self::refreshToken()),
            new FakeUserOnAnotherDeviceGrant(self::deviceCode()),
        ]);
    }
}
