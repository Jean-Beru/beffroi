<?php

declare(strict_types=1);

namespace App\Configuration;

use function sprintf;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\ExprBuilder;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\NodeInterface;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Config\Definition\PrototypedArrayNode;

/**
 * The definition of a list of the configuration an environment variable may carry whole (decision 0030): an array
 * node declared as any other, which builds an EnvironmentListNode. A section declares one with the same fluent calls
 * and builds the same definition again where the list reaches its service, so that a list the environment carried is
 * normalized, defaulted and refused by the rules a written one is (normalized()).
 */
final class EnvironmentListDefinition extends ArrayNodeDefinition
{
    private bool $wrapsAString = false;

    /**
     * A string written in the file is the list of that one string, as castToArray() makes it; a placeholder is never
     * wrapped, standing for the list whole, so an environment variable may carry one entry or the list as JSON.
     */
    public function wrapsAString(): static
    {
        $this->wrapsAString = true;

        return $this;
    }

    /**
     * The list as the tree makes a written one, from whatever the environment carried: its entries normalized, their
     * defaults filled in, and what the tree refuses refused.
     *
     * @param string $path the key of the "beffroi" configuration the list is written under, which a refusal names
     *
     * @throws InvalidConfigurationException when the list is one the tree refuses
     *
     * @return array<array-key, mixed>
     */
    public function normalized(mixed $list, string $path): array
    {
        try {
            $normalized = new Processor()->process($this->getNode(true), [$list]);
        } catch (InvalidConfigurationException $refusal) {
            throw new InvalidConfigurationException(
                sprintf(
                    'The "beffroi" configuration key "%s" carried by the environment is refused: %s',
                    $path,
                    $refusal->getMessage(),
                ),
                0,
                $refusal,
            );
        }

        return $normalized;
    }

    /**
     * @throws InvalidConfigurationException when the list declares no shape for its entries
     */
    protected function createNode(): NodeInterface
    {
        // a placeholder, which the node accepts for the list whole, is a string: the reference and the schema say so
        $this->allowedTypes = [...($this->allowedTypes ?? []), ExprBuilder::TYPE_STRING];
        $node = parent::createNode();
        if (! $node instanceof PrototypedArrayNode) {
            throw new InvalidConfigurationException(sprintf('The list "%s" of the configuration declares the shape of its entries.', $this->name ?? ''));
        }

        return EnvironmentListNode::of($node, $this->wrapsAString);
    }
}
