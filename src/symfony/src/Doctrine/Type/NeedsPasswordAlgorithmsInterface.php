<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Port\PasswordAlgorithmsInterface;

/**
 * A DBAL type that reads a password algorithm back and needs the wiring to do it (decision 0002: a hash
 * names its algorithm, and the algorithms are those the deployment is wired with, not an enumeration).
 *
 * The wiring is handed to the class and not to an instance, because no instance of a type exists to
 * receive it: Doctrine registers its types when a connection is first made, long after the bundles have
 * booted, it builds them itself from a class name, and it replaces the instance of a type it is given
 * twice. What the bundle can do once the container is up is tell the class (BeffroiBundle::boot()), and
 * whichever instance Doctrine ends up holding reads it when a row arrives. It is the shape Symfony's own
 * clock has, for the same reason.
 */
interface NeedsPasswordAlgorithmsInterface
{
    public static function resolveWith(PasswordAlgorithmsInterface $algorithms): void;
}
