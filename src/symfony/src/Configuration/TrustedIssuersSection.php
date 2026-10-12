<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Oidc\Application\Trust\IssuerAssertionValidator;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationTrustedIssuers;
use function is_array;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * The third parties whose signature the tenant trusts (architecture §5.1), keyed by the "iss" their assertions
 * carry. Whoever holds the signing key of one of them can name a user of this tenant and be answered with an
 * access token (RFC 7523 §2.1), so everything about it is written down here: the keys, the algorithms, the
 * clients that may present its assertions, the source of the identities it is about and what it is trusted
 * for. A tenant that declares none serves the grant to nobody.
 *
 * What one read of a "jwks_uri" of an issuer costs is read from "client_authentication" (ClientAuthenticationSection),
 * as the window of its assertions is: the bound belongs to the read and not to whoever registered the URL.
 */
final readonly class TrustedIssuersSection extends ConfigurationSection
{
    /**
     * RFC 7523 §3: an assertion is minted for one request. The default is the one client assertions take, for
     * the same reason.
     */
    public const int DEFAULT_ASSERTION_MAX_LIFETIME = 300;

    public const int DEFAULT_ASSERTION_LEEWAY = 30;

    public function name(): string
    {
        return 'trusted_issuers';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('trusted_issuers')
            ->info('The issuers whose assertions this tenant accepts as an authorization (RFC 7523 §2.1), keyed by the "iss" they sign with. Each one is a closed declaration: nothing about it is inferred, and an issuer nobody declared is unknown.')
            ->useAttributeAsKey('issuer')
            ->normalizeKeys(false)
            ->arrayPrototype()
            ->children()
            ->variableNode('jwks')
            ->info('The JWK Set of the issuer, inline (RFC 7517 §5): public keys only, and the only keys an assertion of this issuer is ever verified against, whatever its header names (RFC 8725 §3.10). Either this or "jwks_uri", never both and never neither.')
            ->defaultNull()
            ->end()
            ->scalarNode('jwks_uri')
            ->info('Where the JWK Set of the issuer is read back from instead (RFC 7517 §5), which is how an issuer that rotates its keys publishes them: one GET over HTTPS, no redirect followed, read once and kept in a pool the workers share, and read again at most once per cooldown when an assertion names a "kid" the kept set does not hold. Either this or "jwks", never both and never neither.')
            ->defaultNull()
            ->end()
            ->arrayNode('signing_algorithms')
            ->info('The JWS algorithms an assertion of this issuer may be signed with (RFC 7515 §4.1.1), among those the provider is wired with; at least one. A name nothing verifies fails at boot.')
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('clients')
            ->info('The clients that may present an assertion of this issuer at the token endpoint, by client identifier; at least one. An issuer trusted for a gateway is not thereby trusted for every client of the tenant.')
            ->scalarPrototype()
            ->end()
            ->end()
            ->scalarNode('identity_provider')
            ->info('The source of the linked identities the subjects of its assertions name (decision 0002): the "sub" of an assertion is a user of this tenant only when a linked identity of that source says so, and no user is ever created here.')
            ->defaultNull()
            ->end()
            ->arrayNode('trusted_scopes')
            ->info('What this issuer is trusted for: the scopes of a response are a subset of these, of what the client registered and of what the request asked for. "openid" among them buys nothing, the grant refusing it: it authenticates nobody.')
            ->scalarPrototype()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $services->get(ConfigurationTrustedIssuers::class)->arg('$tenantSlug', self::string(self::section($config, 'tenant'), 'slug'))->arg(
            '$definitions',
            is_array($config['trusted_issuers'] ?? null) ? $config['trusted_issuers'] : [],
        );
        $clientAuthentication = self::section($config, 'client_authentication');
        $services->get(IssuerAssertionValidator::class)->arg('$maximumLifetime', self::seconds(
            $clientAuthentication,
            'assertion_max_lifetime',
        ))->arg('$leeway', self::seconds($clientAuthentication, 'assertion_leeway'));
        $services->get('beffroi.oidc.issuer_keys.provider')->arg('$cooldown', self::seconds($clientAuthentication, 'jwks_refetch_cooldown'));
        $services->get('beffroi.oidc.issuer_keys.cache')->arg('$lifetime', self::integer($clientAuthentication, 'jwks_ttl'));
    }
}
