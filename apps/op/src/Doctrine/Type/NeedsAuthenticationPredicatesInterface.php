<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Beffroi\Core\Port\AuthenticationPredicatesInterface;

/**
 * A DBAL type that reads an authentication predicate back and needs the wiring to do it (decision 0010: a
 * stored policy and a stored floor name a predicate, and the predicates are those the deployment is wired
 * with, not an enumeration).
 *
 * The wiring goes to the class and not to an instance, for the reason NeedsPasswordAlgorithmsInterface
 * gives: no instance of a type exists while the bundles boot, Doctrine building them itself when a
 * connection is first made.
 */
interface NeedsAuthenticationPredicatesInterface
{
    public static function resolveWith(AuthenticationPredicatesInterface $predicates): void;
}
