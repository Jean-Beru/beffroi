<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Core\Application\Identity\ClaimHistoryRetention;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * How long the history of what a record used to say keeps a change (issue #482). There is nothing here to
 * turn it on: a person who changes a claim of theirs gets the change written down, and what a deployment
 * decides is for how long.
 */
final readonly class HistorySection extends ConfigurationSection
{
    /**
     * The duration the journal keeps an act, and for a reason of this provider rather than of a text: a
     * change and the act that announced it are two halves of one answer, so keeping one longer than the
     * other leaves an act whose change is gone, or a change whose act is gone. A deployment that moves
     * one moves both.
     */
    public const int DEFAULT_RETENTION = JournalSection::DEFAULT_RETENTION;

    public function name(): string
    {
        return 'history';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('history')
            ->info('What a claim of a person used to say, and what they made it say (issue #482). Nothing turns it on; what is configured is how long a change is kept.')
            ->addDefaultsIfNotSet()
            ->children()
            ->integerNode('retention')
            ->info('Days a change is kept before the timed step forgets it; the duration the journal keeps an act, a change and the act that announced it being two halves of one answer.')
            ->min(1)
            ->defaultValue(self::DEFAULT_RETENTION)
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $services->get(ClaimHistoryRetention::class)->arg('$days', self::integer($this->own($config), 'retention'));
    }
}
