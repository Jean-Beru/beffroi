<?php

declare(strict_types=1);

namespace App\Configuration;

use App\Client\ClientJwksFetcher;
use App\Http\Timeout;
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
            ->min(Timeout::MINIMUM)
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
        $services->get(ClientAssertionValidator::class)->arg('$maximumLifetime', self::assertionLifetime($clientAuthentication))->arg(
            '$leeway',
            self::assertionLeeway($clientAuthentication),
        );
        $services->get('beffroi.oidc.client_keys.provider')->arg('$cooldown', self::refetchCooldown($clientAuthentication));
        $services->get(ClientJwksFetcher::class)->arg('$timeout', self::timeout(
            $clientAuthentication,
            'jwks_timeout',
            'client_authentication.jwks_timeout',
        ))->arg('$maximumSize', self::bytes($clientAuthentication, 'jwks_max_size', 'client_authentication.jwks_max_size'));
        $services->get('beffroi.oidc.client_keys.cache')->arg('$lifetime', self::keptFor($clientAuthentication));
    }

    /**
     * How far ahead the "exp" of an assertion may be, which the assertions of a client and those of a trusted issuer
     * are both held to (TrustedIssuersSection), as the container builds it from this section.
     *
     * @param array<array-key, mixed> $clientAuthentication
     */
    public static function assertionLifetime(array $clientAuthentication): object
    {
        return self::bounded($clientAuthentication, 'assertion_max_lifetime', named: 'client_authentication.assertion_max_lifetime');
    }

    /**
     * What is allowed of the clock of whoever signs an assertion, a client or a trusted issuer.
     *
     * @param array<array-key, mixed> $clientAuthentication
     */
    public static function assertionLeeway(array $clientAuthentication): object
    {
        return self::bounded($clientAuthentication, 'assertion_leeway', named: 'client_authentication.assertion_leeway', minimum: 0);
    }

    /**
     * How often an unknown "kid" may cost a read of a published set, a client's or a trusted issuer's.
     *
     * @param array<array-key, mixed> $clientAuthentication
     */
    public static function refetchCooldown(array $clientAuthentication): object
    {
        return self::bounded($clientAuthentication, 'jwks_refetch_cooldown', named: 'client_authentication.jwks_refetch_cooldown', minimum: 0);
    }

    /**
     * How long the keys read back from a published set are kept, a client's or a trusted issuer's.
     *
     * @param array<array-key, mixed> $clientAuthentication
     */
    public static function keptFor(array $clientAuthentication): object
    {
        return self::bounded($clientAuthentication, 'jwks_ttl', named: 'client_authentication.jwks_ttl');
    }
}
