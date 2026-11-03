<?php

declare(strict_types=1);

namespace App\Configuration;

use function is_string;
use ReflectionClass;
use ReflectionProperty;
use Symfony\Component\Config\Definition\ArrayNode;
use Symfony\Component\Config\Definition\BaseNode;
use Symfony\Component\Config\Definition\PrototypedArrayNode;

/**
 * A list of the configuration that an environment variable may carry whole (decision 0030): an array node accepts no
 * placeholder in symfony/config 8.2, so this one is the node Symfony builds from its definition, its shape, its
 * defaults and its documentation unchanged, with one difference. While a placeholder stands for the list, the tree
 * checks nothing of it, a placeholder being a value only at runtime; the list is held to the same tree then, by the
 * service it reaches (EnvironmentListDefinition::normalized()). A list written in the file is checked as Symfony
 * checks it.
 *
 * It is built by copying the state of the node Symfony built, which is what keeps every rule of the definition
 * without restating one of them; it is the bridge until an array node of Symfony accepts a placeholder itself.
 */
final class EnvironmentListNode extends PrototypedArrayNode
{
    /**
     * Whether a string written in the file is the list of that one string. A placeholder is never wrapped: it stands
     * for the list whole, whatever the environment carries.
     */
    private bool $wrapsAString = false;

    /**
     * The node Symfony built, as a list the environment may carry: every property of the three classes copied, and
     * the prototype made a child of the copy.
     */
    public static function of(PrototypedArrayNode $built, bool $wrapsAString = false): self
    {
        $list = new ReflectionClass(self::class)->newInstanceWithoutConstructor();
        foreach ([BaseNode::class, ArrayNode::class, PrototypedArrayNode::class] as $class) {
            foreach (new ReflectionClass($class)->getProperties() as $property) {
                if ($property->isStatic() || $property->getDeclaringClass()->getName() !== $class || ! $property->isInitialized($built)) {
                    continue;
                }
                $property->setValue($list, $property->getValue($built));
            }
        }
        $prototype = $list->getPrototype();
        if ($prototype instanceof BaseNode) {
            new ReflectionProperty(BaseNode::class, 'parent')->setValue($prototype, $list);
        }
        $list->wrapsAString = $wrapsAString;

        return $list;
    }

    protected function allowPlaceholders(): bool
    {
        return true;
    }

    protected function validateType(mixed $value): void
    {
        if ($this->isHandlingPlaceholder() || $this->wrapsAString && is_string($value)) {
            return;
        }
        parent::validateType($value);
    }

    protected function normalizeValue(mixed $value): mixed
    {
        if ($this->isHandlingPlaceholder()) {
            return $value;
        }

        return parent::normalizeValue($this->wrapsAString && is_string($value) ? [$value] : $value);
    }

    protected function mergeValues(mixed $leftSide, mixed $rightSide): mixed
    {
        return $this->isHandlingPlaceholder() ? $rightSide : parent::mergeValues($leftSide, $rightSide);
    }

    protected function finalizeValue(mixed $value): mixed
    {
        return $this->isHandlingPlaceholder() ? $value : parent::finalizeValue($value);
    }
}
