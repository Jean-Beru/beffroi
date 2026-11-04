<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Token\BackchannelAuthenticationGrant;
use Beffroi\Oidc\Application\Token\JwtBearerGrant;
use Beffroi\Oidc\Application\Token\TokenExchangeGrant;
use Beffroi\Oidc\Application\Token\ServedGrants;
use Beffroi\Oidc\Domain\Client\GrantTypeName;

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

    public static function ciba(): GrantTypeName
    {
        return new GrantTypeName(BackchannelAuthenticationGrant::GRANT_TYPE);
    }

    public static function tokenExchange(): GrantTypeName
    {
        return new GrantTypeName(TokenExchangeGrant::GRANT_TYPE);
    }

    public static function jwtBearer(): GrantTypeName
    {
        return new GrantTypeName(JwtBearerGrant::GRANT_TYPE);
    }

    /**
     * RFC 6749 §4.5, RFC 6755
     */
    public static function invented(): GrantTypeName
    {
        return new GrantTypeName('urn:example:params:oauth:grant-type:invented');
    }

    public static function served(): ServedGrants
    {
        return new ServedGrants([
            new FakeRefreshTokenIssuingGrant(self::authorizationCode()),
            new FakeRefreshTokenSpendingGrant(self::refreshToken()),
        ]);
    }

    /**
     * RFC 6749 §4.4
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
     * RFC 8628 §3.3
     */
    public static function servedWithDeviceCode(): ServedGrants
    {
        return new ServedGrants([
            new FakeRefreshTokenIssuingGrant(self::authorizationCode()),
            new FakeRefreshTokenSpendingGrant(self::refreshToken()),
            new FakeUserOnAnotherDeviceGrant(self::deviceCode()),
        ]);
    }

    /**
     * RFC 8693 §2.1
     */
    public static function servedWithTokenExchange(): ServedGrants
    {
        return new ServedGrants([
            new FakeRefreshTokenIssuingGrant(self::authorizationCode()),
            new FakeRefreshTokenSpendingGrant(self::refreshToken()),
            new FakeExchangingGrant(self::tokenExchange()),
        ]);
    }

    /**
     * RFC 7523 §2.1
     */
    public static function servedWithJwtBearer(): ServedGrants
    {
        return new ServedGrants([
            new FakeRefreshTokenIssuingGrant(self::authorizationCode()),
            new FakeRefreshTokenSpendingGrant(self::refreshToken()),
            new FakeClientAuthenticatingGrant(self::jwtBearer()),
        ]);
    }

    /**
     * CIBA Core §7
     */
    public static function servedWithCiba(): ServedGrants
    {
        return new ServedGrants([
            new FakeRefreshTokenIssuingGrant(self::authorizationCode()),
            new FakeRefreshTokenSpendingGrant(self::refreshToken()),
            new FakeBackchannelGrant(self::ciba()),
        ]);
    }
}
