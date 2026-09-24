<?php

declare(strict_types=1);

namespace Heidi\Bundle\Configuration;

use Heidi\Bundle\Client\RequestObjectFetcher;
use Heidi\Oidc\Application\Authorization\RequestObjectValidator;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * What the provider allows of a request object a client signs (RFC 9101 §4), and what one read of a "request_uri" may cost: a browser is waiting on it.
 */
final readonly class RequestObjectsSection extends ConfigurationSection
{
    /**
     * RFC 9101 §4: how long a request object may stand, from its "nbf". One hour is what FAPI 2.0
     * Message Signing allows; an object is a request made now, not an authorization kept for a day.
     */
    public const int DEFAULT_REQUEST_OBJECT_MAX_LIFETIME = 3600;

    /**
     * What is allowed of the clock of a client, both ways.
     */
    public const int DEFAULT_REQUEST_OBJECT_LEEWAY = 30;

    /**
     * Seconds one read of a "request_uri" is given, connection included: the browser of a user is
     * waiting on it.
     */
    public const float DEFAULT_REQUEST_OBJECT_TIMEOUT = 3.0;

    /**
     * Bytes a "request_uri" may answer; a request object carries the parameters of one request.
     */
    public const int DEFAULT_REQUEST_OBJECT_MAX_SIZE = 65536;

    public function name(): string
    {
        return 'request_objects';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('request_objects')
            ->info('How a request the client carried in a JWT is read (RFC 9101 §4, OIDC Core §6). Which algorithm verifies it is the wiring and the registration of the client, not this; an unsigned object is read from a client that registered "none" and from no other.')
            ->addDefaultsIfNotSet()
            ->children()
            ->integerNode('max_lifetime')
            ->info('Seconds a request object may stand, from its "nbf" (RFC 9101 §4). An object is a request made now; a long one is an authorization a client keeps.')
            ->defaultValue(self::DEFAULT_REQUEST_OBJECT_MAX_LIFETIME)
            ->min(1)
            ->end()
            ->integerNode('leeway')
            ->info('Seconds allowed of the clock of a client, both ways.')
            ->defaultValue(self::DEFAULT_REQUEST_OBJECT_LEEWAY)
            ->min(0)
            ->end()
            ->floatNode('timeout')
            ->info('Seconds one read of a request_uri is given, connection included. The browser of a user is waiting on it; no redirect is followed and only a URL the client registered is ever read.')
            ->defaultValue(self::DEFAULT_REQUEST_OBJECT_TIMEOUT)
            ->min(0.1)
            ->end()
            ->integerNode('max_size')
            ->info('Bytes a request_uri may answer before the read stops; a request object carries the parameters of one request.')
            ->defaultValue(self::DEFAULT_REQUEST_OBJECT_MAX_SIZE)
            ->min(1)
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $requestObjects = $this->own($config);
        $services->get(RequestObjectValidator::class)->arg('$maximumLifetime', self::seconds($requestObjects, 'max_lifetime'))->arg('$leeway', self::seconds(
            $requestObjects,
            'leeway',
        ));
        $services->get(RequestObjectFetcher::class)->arg('$timeout', self::float($requestObjects, 'timeout'))->arg('$maximumSize', self::integer(
            $requestObjects,
            'max_size',
        ));
    }
}
