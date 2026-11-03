<?php

declare(strict_types=1);

namespace App\Configuration;

use function array_any;
use Closure;

/**
 * Whether a role a deployment plays is on (decision 0030): the SAML identity provider, the SAML service provider, web
 * push. The routes and the tags of a role are wired in every image, the container needing them when it is compiled,
 * and whether it is on is a value an environment variable may carry, a value only once the container runs. So it is
 * read once, when the container builds a service the role changes, and decides then what that service is built with:
 * the handler of the role or none (served()), a list with what the role brings or without it (SwitchedServices). A role
 * that is off is answered as one that was never declared, by the same 404, the same lists and the same dormant keys
 * (DormantKeyAlgorithms).
 */
final readonly class RoleSwitch
{
    public function __construct(
        public bool $on,
    ) {
    }

    /**
     * A role that is on while any of those is, as the SAML key is the key of both SAML roles (spec/saml.md S-40).
     *
     * @param list<self> $roles
     */
    public static function anyOf(array $roles): self
    {
        return new self(array_any($roles, static fn (self $role): bool => $role->on));
    }

    /**
     * What a service that depends on the role is handed: the service while the role is on, and none while it is off,
     * which is what a deployment that never declared the role hands it.
     *
     * @template T of object
     *
     * @param Closure(): T $service
     *
     * @return T|null
     */
    public function served(Closure $service): ?object
    {
        return $this->on ? $service() : null;
    }
}
