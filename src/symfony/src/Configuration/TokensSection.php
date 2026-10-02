<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Oidc\Application\Authorization\AuthorizationCodeIssuer;
use Beffroi\Oidc\Application\Ciba\BackchannelAuthenticationHandler;
use Beffroi\Oidc\Application\Device\DeviceAuthorizationHandler;
use Beffroi\Oidc\Application\PushedAuthorization\PushedAuthorizationHandler;
use Beffroi\Oidc\Application\Token\AuthorizationCodeGrant;
use Beffroi\Oidc\Application\Token\BackchannelAuthenticationGrant;
use Beffroi\Oidc\Application\Token\DeviceCodeGrant;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Application\Token\JwtIdTokenIssuer;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Beffroi\Oidc\Application\Token\TokenIssuer;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * How long what the provider issues stands (architecture §9). The bounds are the ones the specifications make, and a deployment may shorten but never lengthen past them.
 */
final readonly class TokensSection extends ConfigurationSection
{
    /**
     * RFC 6749 §4.1.2, the recommendation made a bound.
     */
    public const int MAX_AUTHORIZATION_CODE_TTL = 600;

    /**
     * RFC 9126 §2.2: "typically be relatively short (e.g., between 5 and 600 seconds)", the upper end
     * made a bound; a reference the provider holds is a request nobody has consented to yet.
     */
    public const int MAX_REQUEST_URI_TTL = 600;

    /**
     * RFC 8628 §3.2: a code a user reads off a screen and types elsewhere needs minutes, and thirty of them
     * are as long as a code of thirty-four bits may be guessed at (§5.1), whatever the rate.
     */
    public const int MAX_DEVICE_CODE_TTL = 1800;

    /**
     * RFC 8628 §3.5: an interval a client is asked to respect is one it can respect; a minute between two
     * polls would make the flow slower than the code lives.
     */
    public const int MAX_DEVICE_CODE_INTERVAL = 30;

    /**
     * CIBA Core §7.1: a request somebody has to be reached about and then answer needs minutes, and an
     * hour is as long as a provider should hold one open for a user who is not going to answer it.
     */
    public const int MAX_BACKCHANNEL_AUTHENTICATION_TTL = 3600;

    /**
     * CIBA Core §11: an interval a client is asked to respect is one it can respect, as for the device
     * grant, and for the same reason.
     */
    public const int MAX_BACKCHANNEL_AUTHENTICATION_INTERVAL = 30;

    public function name(): string
    {
        return 'tokens';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('tokens')
            ->info('Lifetimes in seconds. The defaults are the choices of architecture §9.')
            ->addDefaultsIfNotSet()
            ->children()
            ->integerNode('authorization_code_ttl')
            ->info('RFC 6749 §4.1.2 recommends ten minutes at most; sixty seconds bound the injection window.')
            ->defaultValue(60)
            ->min(1)
            ->max(self::MAX_AUTHORIZATION_CODE_TTL)
            ->end()
            ->integerNode('access_token_ttl')
            ->info('Both shapes of access token (architecture §4.6): the self-contained one cannot be revoked, and a short lifetime bounds the exposure; the opaque one gets the same, a revocation is a facility and not a reason to live longer.')
            ->defaultValue(600)
            ->min(1)
            ->end()
            ->integerNode('id_token_ttl')
            ->defaultValue(600)
            ->min(1)
            ->end()
            ->integerNode('request_uri_ttl')
            ->info('Seconds a request_uri answered by the pushed authorization request endpoint lives (RFC 9126 §2.2); sixty is the example of the specification, and the browser is sent the moment the client holds the reference.')
            ->defaultValue(60)
            ->min(1)
            ->max(self::MAX_REQUEST_URI_TTL)
            ->end()
            ->integerNode('device_code_ttl')
            ->info('Seconds a device code and the user code beside it live (RFC 8628 §3.2); ten minutes is what a user needs to read a code off one screen and type it on another.')
            ->defaultValue(600)
            ->min(1)
            ->max(self::MAX_DEVICE_CODE_TTL)
            ->end()
            ->integerNode('device_code_interval')
            ->info('Seconds a client waits between two polls of the token endpoint (RFC 8628 §3.2); five is the default of the specification, and a client that polls faster is told to add five.')
            ->defaultValue(5)
            ->min(1)
            ->max(self::MAX_DEVICE_CODE_INTERVAL)
            ->end()
            ->integerNode('backchannel_authentication_ttl')
            ->info('Seconds a backchannel authentication request lives when the client asks for nothing (CIBA Core §7.3); five minutes is what somebody needs to be reached and to answer.')
            ->defaultValue(300)
            ->min(1)
            ->max(self::MAX_BACKCHANNEL_AUTHENTICATION_TTL)
            ->end()
            ->integerNode('backchannel_authentication_max_requested_expiry')
            ->info('Seconds the longest lifetime a client may ask for with "requested_expiry" (CIBA Core §7.1); a request that asks for more is served this, not refused.')
            ->defaultValue(1800)
            ->min(1)
            ->max(self::MAX_BACKCHANNEL_AUTHENTICATION_TTL)
            ->end()
            ->integerNode('backchannel_authentication_interval')
            ->info('Seconds a client waits between two polls of the token endpoint for a backchannel request (CIBA Core §7.3); five is the default of the specification, and a client that polls faster is told to add five.')
            ->defaultValue(5)
            ->min(1)
            ->max(self::MAX_BACKCHANNEL_AUTHENTICATION_INTERVAL)
            ->end()
            ->integerNode('refresh_token_ttl')
            ->info('Sliding lifetime of a refresh token, renewed at each rotation.')
            ->defaultValue(2592000)
            ->min(1)
            ->end()
            ->integerNode('refresh_token_absolute_ttl')
            ->info('Lifetime of a refresh token family from the authorization that started it; no rotation extends it.')
            ->defaultValue(7776000)
            ->min(1)
            ->end()
            ->end()
            ->validate()
            ->ifTrue(
                static fn (array $tokens): bool => (
                    is_int($tokens['refresh_token_ttl'])
                    && is_int($tokens['refresh_token_absolute_ttl'])
                    && $tokens['refresh_token_ttl'] > $tokens['refresh_token_absolute_ttl']
                ),
            )
            ->thenInvalid('The sliding lifetime of a refresh token (refresh_token_ttl) cannot exceed the absolute lifetime of its family (refresh_token_absolute_ttl).')
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $tokens = $this->own($config);
        $services->get(AuthorizationCodeIssuer::class)->arg('$lifetime', self::seconds($tokens, 'authorization_code_ttl'));
        $services->get(PushedAuthorizationHandler::class)->arg('$lifetime', self::seconds($tokens, 'request_uri_ttl'));
        $services->get(JwtAccessTokenIssuer::class)->arg('$lifetime', self::seconds($tokens, 'access_token_ttl'));
        $services->get(OpaqueAccessTokenIssuer::class)->arg('$lifetime', self::seconds($tokens, 'access_token_ttl'));
        $services->get(JwtIdTokenIssuer::class)->arg('$lifetime', self::seconds($tokens, 'id_token_ttl'));
        $services->get(TokenIssuer::class)->arg('$refreshTokenLifetime', self::seconds($tokens, 'refresh_token_ttl'));
        $services->get(AuthorizationCodeGrant::class)->arg('$refreshTokenFamilyLifetime', self::seconds($tokens, 'refresh_token_absolute_ttl'));
        $services->get(DeviceCodeGrant::class)->arg('$refreshTokenFamilyLifetime', self::seconds($tokens, 'refresh_token_absolute_ttl'));
        $services->get(DeviceAuthorizationHandler::class)->arg('$lifetime', self::seconds($tokens, 'device_code_ttl'));
        $services->get(DeviceAuthorizationHandler::class)->arg('$interval', self::integer($tokens, 'device_code_interval'));
        $services->get(BackchannelAuthenticationGrant::class)->arg('$refreshTokenFamilyLifetime', self::seconds($tokens, 'refresh_token_absolute_ttl'));
        $services->get(BackchannelAuthenticationHandler::class)->arg('$lifetime', self::seconds($tokens, 'backchannel_authentication_ttl'));
        $services->get(BackchannelAuthenticationHandler::class)->arg(
            '$maxRequestedExpiry',
            self::seconds($tokens, 'backchannel_authentication_max_requested_expiry'),
        );
        $services->get(BackchannelAuthenticationHandler::class)->arg('$interval', self::integer($tokens, 'backchannel_authentication_interval'));
    }
}
