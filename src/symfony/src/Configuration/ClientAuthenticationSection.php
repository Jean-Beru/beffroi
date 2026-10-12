<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Bundle\Client\ClientJwksFetcher;
use Beffroi\Oidc\Application\Client\ClientAssertionValidator;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * What the provider allows of an assertion a client signs (RFC 7523 §3) and of the JWK Set a client publishes (RFC 7591 §2): how long one stands, and what one read of a "jwks_uri" may cost.
 *
 * What a read of a "jwks_uri" costs is a property of the read and not of whoever registered the URL, so the
 * four options below bound the reads of every published set: those of the clients, and those of the issuers a
 * tenant trusts, which TrustedIssuersSection reads here for the same reason it reads the assertion window
 * here (RFC 7523 §3).
 */
final readonly class ClientAuthenticationSection extends ConfigurationSection
{
    /**
     * RFC 7523 §3: how far ahead of the request the "exp" of a client assertion may be. Five minutes is
     * what the field sends; an assertion is minted for one request, not kept.
     */
    public const int DEFAULT_ASSERTION_MAX_LIFETIME = 300;

    /**
     * What is allowed of the clock of a client, both ways.
     */
    public const int DEFAULT_ASSERTION_LEEWAY = 30;

    /**
     * Seconds one read of a "jwks_uri" is given, connection included: an endpoint authenticating a client
     * is waiting on it.
     */
    public const float DEFAULT_JWKS_TIMEOUT = 3.0;

    /**
     * Bytes a "jwks_uri" may answer; a JWK Set of a client holds a handful of public keys.
     */
    public const int DEFAULT_JWKS_MAX_SIZE = 65536;

    /**
     * How long the keys read back from a "jwks_uri" are kept.
     */
    public const int DEFAULT_JWKS_TTL = 86400;

    /**
     * How often an unknown "kid" may cost a read of a "jwks_uri", the symmetric of the cooldown of
     * Symfony's own client (spike 2).
     */
    public const int DEFAULT_JWKS_REFETCH_COOLDOWN = 300;

    public function name(): string
    {
        return 'client_authentication';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('client_authentication')
            ->info('How a client proves who it is at the endpoints that authenticate one (RFC 6749 §2.3, OIDC Core §9). Which methods the provider takes is the wiring, not this: a method is a tagged service, and what is tagged is what is announced.')
            ->addDefaultsIfNotSet()
            ->children()
            ->integerNode('assertion_max_lifetime')
            ->info('Seconds ahead of the request the "exp" of a client assertion may be (RFC 7523 §3). An assertion is minted for one request; a long one is a bearer token nobody watches.')
            ->defaultValue(self::DEFAULT_ASSERTION_MAX_LIFETIME)
            ->min(1)
            ->end()
            ->integerNode('assertion_leeway')
            ->info('Seconds allowed of the clock of a client, both ways.')
            ->defaultValue(self::DEFAULT_ASSERTION_LEEWAY)
            ->min(0)
            ->end()
            ->floatNode('jwks_timeout')
            ->info('Seconds one read of a jwks_uri is given, connection included. A client that hangs must not hold a worker: an endpoint authenticating it is waiting.')
            ->defaultValue(self::DEFAULT_JWKS_TIMEOUT)
            ->min(0.1)
            ->end()
            ->integerNode('jwks_max_size')
            ->info('Bytes a jwks_uri may answer before the read stops; a JWK Set of a client holds a handful of public keys.')
            ->defaultValue(self::DEFAULT_JWKS_MAX_SIZE)
            ->min(1)
            ->end()
            ->integerNode('jwks_ttl')
            ->info('Seconds the keys read back from a jwks_uri are kept in the pool the workers share.')
            ->defaultValue(self::DEFAULT_JWKS_TTL)
            ->min(1)
            ->end()
            ->integerNode('jwks_refetch_cooldown')
            ->info('Seconds between two reads of the same jwks_uri when an assertion names a "kid" the kept set does not hold. A client that rotates a key is followed within one request; a client that signs with a key it never published cannot make the provider call it on every request.')
            ->defaultValue(self::DEFAULT_JWKS_REFETCH_COOLDOWN)
            ->min(0)
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $clientAuthentication = $this->own($config);
        $services->get(ClientAssertionValidator::class)->arg('$maximumLifetime', self::seconds(
            $clientAuthentication,
            'assertion_max_lifetime',
        ))->arg('$leeway', self::seconds($clientAuthentication, 'assertion_leeway'));
        $services->get('beffroi.oidc.client_keys.provider')->arg('$cooldown', self::seconds($clientAuthentication, 'jwks_refetch_cooldown'));
        $services->get(ClientJwksFetcher::class)->arg('$timeout', self::float($clientAuthentication, 'jwks_timeout'))->arg('$maximumSize', self::integer(
            $clientAuthentication,
            'jwks_max_size',
        ));
        $services->get('beffroi.oidc.client_keys.cache')->arg('$lifetime', self::integer($clientAuthentication, 'jwks_ttl'));
    }
}
