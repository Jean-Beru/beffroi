<?php

declare(strict_types=1);

namespace Heidi\Bundle\Configuration;

use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * One capability of the provider, as a deployment configures it (architecture §5.1): the key it is
 * written under, what may be written there, and what those values change in the wiring.
 *
 * Declaring and loading are one class because they are one decision: an option that exists and reaches
 * nothing, or a service argument nothing declares, is what two places drifting apart looks like. A
 * capability the provider grows into is a class here and a line in the bundle; no existing file is
 * edited for its options to exist, be validated and reach its services.
 */
interface ConfigurationSectionInterface
{
    /**
     * The key of the "heidi" configuration this section owns.
     *
     * @return non-empty-string
     */
    public function name(): string;

    /**
     * What may be written under that key, added to the children of the root node.
     */
    public function describe(NodeBuilder $children): void;

    /**
     * What the configured values change in the wiring. The whole configuration is handed over, not only
     * this section, because a capability may be configured by what another one says: the clients of a
     * deployment belong to the tenant it declares.
     *
     * @param array<array-key, mixed> $config the whole "heidi" configuration, validated against the tree
     * @param bool $debug whether the kernel runs in debug, which is the only thing the panel is wired on
     */
    public function load(array $config, ServicesConfigurator $services, bool $debug): void;
}
