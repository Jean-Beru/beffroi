<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Key;

use function implode;
use function is_array;
use function is_string;
use function sprintf;
use function str_starts_with;
use function strlen;
use function substr;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;

/**
 * Checks the KMS client the bundle is pointed at against the clients the framework configuration
 * registers.
 *
 * The bundle seals with a client it does not build: "beffroi.keys.kms" names an entry of
 * "key_management.clients" and "beffroi.kms" is an alias to it. A name nothing answers to would
 * otherwise fail the build on a service id, which names neither the option that holds the name nor
 * the names that would have worked; a name is what an operator wrote, so a name is what the failure
 * says.
 */
final class KmsClientPass implements CompilerPassInterface
{
    /**
     * The alias the bundle registers, and the prefix of the clients the framework registers.
     */
    public const string ALIAS = 'beffroi.kms';

    public const string PREFIX = 'key_management.';

    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasAlias(self::ALIAS)) {
            return;
        }

        $target = (string) $container->getAlias(self::ALIAS);
        if ($container->has($target)) {
            return;
        }

        throw new LogicException(sprintf(
            'The KMS client "%s" named by the "beffroi.keys.kms" configuration is not registered in "key_management.clients": %s.',
            str_starts_with($target, self::PREFIX) ? substr($target, strlen(self::PREFIX)) : $target,
            self::registered($container),
        ));
    }

    /**
     * The clients that would have answered, by the name they carry on their tag.
     */
    private static function registered(ContainerBuilder $container): string
    {
        $names = [];
        foreach ($container->findTaggedServiceIds('key_management.client') as $id => $tags) {
            $tag = $tags[0] ?? [];
            $name = is_array($tag) ? $tag['key'] ?? $id : $id;
            $names[] = is_string($name) ? $name : $id;
        }

        if ($names === []) {
            return 'no client is registered at all';
        }

        return sprintf('the registered ones are "%s"', implode('", "', $names));
    }
}
