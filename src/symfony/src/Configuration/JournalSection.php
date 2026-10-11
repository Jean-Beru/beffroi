<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Core\Application\Journal\JournalRetention;
use Beffroi\Oidc\Application\Disclosure\DisclosureRetention;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * How long the journal of the acts keeps one (issue #454). There is nothing here to turn it on: every act
 * is written down, and what a deployment decides is for how long.
 */
final readonly class JournalSection extends ConfigurationSection
{
    /**
     * Six months, which is the duration the deliberation 2021-122 of the CNIL holds for a log of
     * connections kept for the security of a service. It is a default and not a rule written in code: a
     * deployment under another obligation says its own, and a deployment that must keep a year says a
     * year without touching anything else.
     */
    public const int DEFAULT_RETENTION = 180;

    public function name(): string
    {
        return 'journal';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('journal')
            ->info('The acts of the provider, written down and forgotten again (issue #454): who did what, when and from where. Nothing turns it on; what is configured is how long an act is kept.')
            ->addDefaultsIfNotSet()
            ->children()
            ->integerNode('retention')
            ->info('Days an act is kept before the timed step forgets it; six months by default, the duration the deliberation 2021-122 of the CNIL holds for a log of connections. A deployment under another obligation says its own.')
            ->min(1)
            ->defaultValue(self::DEFAULT_RETENTION)
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $own = $this->own($config);
        $services->get(JournalRetention::class)->arg('$window', self::days($own, 'retention'));
        // what a client was given of a person is forgotten with the act that gave it (issue #590): one
        // window for the two tables, because an act whose row is gone, or a row whose act is gone, is
        // half an answer
        $services->get(DisclosureRetention::class)->arg('$window', self::days($own, 'retention'));
    }
}
