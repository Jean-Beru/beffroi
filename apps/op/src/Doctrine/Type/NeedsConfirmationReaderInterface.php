<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Beffroi\Oidc\Port\ConfirmationReaderInterface;

/**
 * A DBAL type that reads back what a token is bound to and needs the wiring to do it: the members of a
 * "cnf" are what the kinds the deployment is wired with answer for, not an enumeration.
 *
 * The wiring is handed to the class and not to an instance, for the reason
 * NeedsPasswordAlgorithmsInterface gives: Doctrine builds its types itself, from a class name, when a
 * connection is first made, so no instance of one exists while the bundles boot.
 */
interface NeedsConfirmationReaderInterface
{
    public static function resolveWith(ConfirmationReaderInterface $confirmations): void;
}
