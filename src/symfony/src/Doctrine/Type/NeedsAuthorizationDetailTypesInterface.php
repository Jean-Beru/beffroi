<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use Heidi\Oidc\Port\AuthorizationDetailsReaderInterface;

/**
 * A DBAL type that reads back what a user agreed to beyond the scopes (RFC 9396 §2) and needs the wiring
 * to do it: what an "authorization_details" means is what the types the deployment is wired with answer
 * for, not an enumeration.
 *
 * The wiring is handed to the class and not to an instance, for the reason
 * NeedsPasswordAlgorithmsInterface gives: Doctrine builds its types itself, from a class name, when a
 * connection is first made, so no instance of one exists while the bundles boot.
 */
interface NeedsAuthorizationDetailTypesInterface
{
    public static function resolveWith(AuthorizationDetailsReaderInterface $types): void;
}
