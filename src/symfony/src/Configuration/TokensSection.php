<?php

declare(strict_types=1);

namespace Heidi\Bundle\Configuration;

use Heidi\Oidc\Application\Authorization\AuthorizationHandler;
use Heidi\Oidc\Application\PushedAuthorization\PushedAuthorizationHandler;
use Heidi\Oidc\Application\Token\AuthorizationCodeGrant;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;
use Heidi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Heidi\Oidc\Application\Token\TokenIssuer;
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
        $services->get(AuthorizationHandler::class)->arg('$codeLifetime', self::seconds($tokens, 'authorization_code_ttl'));
        $services->get(PushedAuthorizationHandler::class)->arg('$lifetime', self::seconds($tokens, 'request_uri_ttl'));
        $services->get(JwtAccessTokenIssuer::class)->arg('$lifetime', self::seconds($tokens, 'access_token_ttl'));
        $services->get(OpaqueAccessTokenIssuer::class)->arg('$lifetime', self::seconds($tokens, 'access_token_ttl'));
        $services->get(JwtIdTokenIssuer::class)->arg('$lifetime', self::seconds($tokens, 'id_token_ttl'));
        $services->get(TokenIssuer::class)->arg('$refreshTokenLifetime', self::seconds($tokens, 'refresh_token_ttl'));
        $services->get(AuthorizationCodeGrant::class)->arg('$refreshTokenFamilyLifetime', self::seconds($tokens, 'refresh_token_absolute_ttl'));
    }
}
