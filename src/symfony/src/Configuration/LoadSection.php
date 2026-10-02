<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Bundle\Load\LoadBudget;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * The two budgets that bound the load a deployment takes (decision 0014): what one origin may send, and
 * what one client may ask once it has authenticated. Their numbers are a function of the size of a
 * deployment and not of the safety of the protocol, so a deployment sets them; their existence is not
 * configurable and there is no key that removes them, whatever its name. The limits that bound a guess,
 * the passwords and the codes of decision 0006, are not here and are not tunable: they count something
 * else, on a subject of their own.
 */
final readonly class LoadSection extends ConfigurationSection
{
    /**
     * Requests a minute from one address. Measured and not chosen: three times the 817 requests the
     * functional suite of this bundle reaches in its busiest minute from one address, which is the
     * fastest sequential client this project has, nothing of a network standing between it and the
     * provider. Three times, because a faster machine sends more in the same minute, and because the
     * refusal this number could cause, a JWK Set refused to a resource server, is the most dangerous
     * one the provider has.
     */
    public const int DEFAULT_ORIGIN_LIMIT = 2400;

    /**
     * Requests a minute from one authenticated client, in one tenant. Half of the budget of an origin
     * rather than anything the measurement gives, the busiest client of that suite asking 34 times in a
     * minute: what this number has to do is name the client that went into a loop before the address it
     * calls from is refused to everybody, and leave room for a resource server that introspects every
     * call it serves.
     */
    public const int DEFAULT_CLIENT_LIMIT = 1200;

    /**
     * The window both budgets count in, in seconds. A minute is the window a burst is read over: short
     * enough that a caller refused is served again while it is still trying, long enough that a client
     * looping does not get a fresh budget between two of its own requests.
     */
    public const int DEFAULT_INTERVAL = 60;

    public function name(): string
    {
        return 'load';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('load')
            ->info('How many requests the provider takes in a window, by origin and by authenticated client (decision 0014). Both budgets always exist; these are their numbers, which depend on the size of the deployment. A number too low on /token or on /jwks is an outage a deployment inflicts on itself, so they are measured on what its own clients send.')
            ->addDefaultsIfNotSet()
            ->children()
            ->arrayNode('origin')
            ->info('What one client address may send, whatever it asks for and whether or not it has proved anything. It is not scoped to a tenant: what it bounds is the load on the machine, which every tenant of a deployment shares.')
            ->addDefaultsIfNotSet()
            ->children()
            ->integerNode('limit')
            ->info('Requests taken from one address in the window.')
            ->defaultValue(self::DEFAULT_ORIGIN_LIMIT)
            ->min(1)
            ->end()
            ->integerNode('interval')
            ->info('Seconds the window covers.')
            ->defaultValue(self::DEFAULT_INTERVAL)
            ->min(1)
            ->end()
            ->end()
            ->end()
            ->arrayNode('client')
            ->info('What one client may ask once its authentication has succeeded, by tenant and by client. This is the one a tenant reads when one of its applications goes into a loop.')
            ->addDefaultsIfNotSet()
            ->children()
            ->integerNode('limit')
            ->info('Requests taken from one authenticated client in the window.')
            ->defaultValue(self::DEFAULT_CLIENT_LIMIT)
            ->min(1)
            ->end()
            ->integerNode('interval')
            ->info('Seconds the window covers.')
            ->defaultValue(self::DEFAULT_INTERVAL)
            ->min(1)
            ->end()
            ->end()
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $load = $this->own($config);
        foreach ([LoadBudget::ORIGIN, LoadBudget::CLIENT] as $budget) {
            $numbers = self::section($load, $budget);
            $services->get('beffroi.load.' . $budget)->arg('$limit', self::integer($numbers, 'limit'))->arg('$interval', self::seconds($numbers, 'interval'));
        }
    }
}
