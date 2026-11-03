<?php

declare(strict_types=1);

namespace App\Doctrine\Listener;

use Beffroi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use ReflectionProperty;

/**
 * Puts the client of a loaded row back on it (architecture §4.1), from the identifier the row kept and
 * the registration the repository resolves for it, set by reflection like the other readonly properties
 * Doctrine hydrates without a constructor. A client no longer registered leaves the property
 * uninitialised; the repositories ask isResolved() and treat the row as absent.
 *
 * Which records those are is not written here: a record that keeps its client that way says so
 * (ResolvesItsClientInterface) and says where the property is held, so a record the provider gains is a
 * record that declares it and a mapping that names this listener, and nothing edited here.
 */
final readonly class ClientResolver
{
    public function __construct(
        private ClientRepositoryInterface $clients,
    ) {
    }

    public function postLoad(ResolvesItsClientInterface $entity): void
    {
        $client = $this->clients->findByClientId($entity->tenant, $entity->clientId);
        if ($client === null) {
            return;
        }
        $holder = $entity->clientHolder();
        self::clientProperty($holder)->setValue($holder, $client);
    }

    public static function isResolved(ResolvesItsClientInterface $entity): bool
    {
        $holder = $entity->clientHolder();

        return self::clientProperty($holder)->isInitialized($holder);
    }

    private static function clientProperty(object $holder): ReflectionProperty
    {
        return new ReflectionProperty($holder::class, 'client');
    }
}
