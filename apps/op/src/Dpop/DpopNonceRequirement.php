<?php

declare(strict_types=1);

namespace App\Dpop;

use Beffroi\Oidc\Port\DpopNonceInterface;
use Closure;

/**
 * Whether this provider asks a proof to carry a nonce of its own (RFC 9449 §8), which is the deployment's to
 * decide, and the class it is wired with for it: the choice is made once, when the container builds the port,
 * and never read again at a request. It is made then and not when the container is compiled because an
 * environment variable is a value only once the container runs, and a deployment says it by one.
 */
final readonly class DpopNonceRequirement
{
    /**
     * @param Closure(): DpopNonceInterface $asked the nonce this provider issues and keeps
     * @param Closure(): DpopNonceInterface $notAsked a provider that asks for none
     */
    public static function chosen(bool $required, Closure $asked, Closure $notAsked): DpopNonceInterface
    {
        return $required ? $asked() : $notAsked();
    }
}
