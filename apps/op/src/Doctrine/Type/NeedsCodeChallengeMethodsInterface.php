<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Beffroi\Oidc\Port\CodeChallengeMethodsInterface;

/**
 * A DBAL type that reads a PKCE method back and needs the wiring to do it (RFC 7636 §4.3: a stored
 * challenge names the method it was made with, and the methods are those the deployment is wired with,
 * not an enumeration).
 *
 * The wiring goes to the class and not to an instance, for the reason NeedsPasswordAlgorithmsInterface
 * gives: no instance of a type exists while the bundles boot, Doctrine building them itself when a
 * connection is first made.
 */
interface NeedsCodeChallengeMethodsInterface
{
    public static function resolveWith(CodeChallengeMethodsInterface $methods): void;
}
