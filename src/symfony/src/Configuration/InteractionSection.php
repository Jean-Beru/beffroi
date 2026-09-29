<?php

declare(strict_types=1);

namespace Heidi\Bundle\Configuration;

use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * What the pages a browser waits on make of the authorization request behind them (architecture §4.3,
 * §5.2). What those pages look like is the integration's and is not here; what they may read of a request
 * is, a hint being worth exactly as much as the provider is wired to read it.
 */
final readonly class InteractionSection extends ConfigurationSection
{
    public function name(): string
    {
        return 'interaction';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('interaction')
            ->info('The pages a browser is sent to while an authorization request waits for a login or a consent (architecture §4.3).')
            ->addDefaultsIfNotSet()
            ->children()
            ->enumNode('login_hint')
            ->info('What a "login_hint" of an authorization request names for this tenant, read one way and never searched for (OIDC Core §3.1.2.1): "sub" the subject this provider issued to that client, "username" the name the user signs in with, "none" for a deployment that tags a reader of its own. The login page offers the name of the user the hint names and nothing at all when it names nobody, the value itself being one the person never typed. These are the names the backchannel flow reads its own hint by.')
            ->values(LoginHintReadings::names())
            ->defaultValue(LoginHintReadings::DEFAULT)
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        LoginHintReadings::tag($services, self::string($this->own($config), 'login_hint'), 'heidi.oidc.login_hint');
    }
}
