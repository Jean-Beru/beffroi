<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Core\Domain\Listing\RetentionWindow;
use DateInterval;
use function is_array;
use function is_bool;
use function is_float;
use function is_int;
use function is_string;
use function sprintf;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;

/**
 * How a section reads what was written under its key. The tree has already refused anything of the
 * wrong shape; what is left is that a value may still be an environment placeholder, a string the
 * container resolves into a number only at runtime, so a section never casts and never assumes.
 */
abstract readonly class ConfigurationSection implements ConfigurationSectionInterface
{
    /**
     * What was written under this section's own key.
     *
     * @param array<array-key, mixed> $config
     *
     * @return array<array-key, mixed>
     */
    protected function own(array $config): array
    {
        return self::section($config, $this->name());
    }

    /**
     * @param array<array-key, mixed> $config
     *
     * @return array<array-key, mixed>
     */
    protected static function section(array $config, string $key): array
    {
        $section = $config[$key] ?? null;

        return is_array($section) ? $section : [];
    }

    /**
     * @param array<array-key, mixed> $section
     */
    protected static function string(array $section, string $key): string
    {
        $value = $section[$key] ?? null;
        if (! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "beffroi" configuration key "%s" must be a string.', $key));
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $section
     *
     * @return int|string a number, or the environment placeholder that stands for it until runtime
     */
    protected static function integer(array $section, string $key): int|string
    {
        $value = $section[$key] ?? null;
        if (! is_int($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "beffroi" configuration key "%s" must be a number.', $key));
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $section
     *
     * @return bool|string a flag, or the environment placeholder the container resolves into one
     */
    protected static function boolean(array $section, string $key): bool|string
    {
        $value = $section[$key] ?? null;
        if (! is_bool($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "beffroi" configuration key "%s" must be true or false.', $key));
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $section
     *
     * @return float|string a number, or the environment placeholder the container resolves into one
     */
    protected static function float(array $section, string $key): float|string
    {
        $value = $section[$key] ?? null;
        if (! is_float($value) && ! is_int($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "beffroi" configuration key "%s" must be a number.', $key));
        }

        return is_int($value) ? (float) $value : $value;
    }

    /**
     * A DateInterval built by the container from a number of seconds.
     *
     * @param array<array-key, mixed> $section
     */
    protected static function seconds(array $section, string $key): object
    {
        $value = $section[$key] ?? null;
        if (! is_int($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "beffroi" configuration key "%s" must be a number of seconds.', $key));
        }

        return inline_service(DateInterval::class)->args(['PT' . $value . 'S']);
    }

    /**
     * A DateInterval built by the container from a number of seconds the tree holds to a second at least and,
     * where it names one, to a maximum, held to the same bounds when it is built: an environment placeholder
     * is a number only then (BoundedLifetime).
     *
     * @param array<array-key, mixed> $section
     * @param string|null $named what the refusal calls the node, its key unless the key alone names several
     */
    protected static function bounded(array $section, string $key, ?int $maximum = null, ?string $named = null): object
    {
        $value = $section[$key] ?? null;
        if (! is_int($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "beffroi" configuration key "%s" must be a number of seconds.', $named ?? $key));
        }

        return inline_service(DateInterval::class)->factory(BoundedLifetime::interval(...))->args([$value, $named ?? $key, $maximum]);
    }

    /**
     * A RetentionWindow built by the container from a number of days: what a store keeps and the moment
     * before which it keeps nothing are one object, so no use case counts days from a number.
     *
     * @param array<array-key, mixed> $section
     */
    protected static function days(array $section, string $key): object
    {
        $value = $section[$key] ?? null;
        if (! is_int($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "beffroi" configuration key "%s" must be a number of days.', $key));
        }

        return inline_service(RetentionWindow::class)->args([$value]);
    }
}
