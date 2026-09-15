<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Listener;

use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\AuthorizationRequest;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use ReflectionProperty;

/**
 * Puts the client back on what a row of the module names by identifier. A client is a registration the
 * module reads from its repository (the configuration in spike 1, architecture §4.1), not a row Doctrine
 * could join: the tables keep "client_id" and, at load, this listener resolves the object the way the
 * endpoints do, from the tenant of the row and the identifier.
 *
 * Doctrine hydrates without a constructor and sets readonly properties by reflection; the one property it
 * cannot map is set the same way. A client that is no longer registered leaves the property uninitialised:
 * the repositories ask isResolved() and treat the row as absent, because a token or a consent of a client
 * that does not exist is not a token or a consent.
 */
final readonly class ClientResolver
{
    public function __construct(
        private ClientRepositoryInterface $clients,
    ) {
    }

    public function postLoad(Interaction|AuthorizationCode|RefreshToken|Consent $entity): void
    {
        $client = $this->clients->findByClientId($entity->tenant, $entity->clientId);
        if ($client === null) {
            return;
        }
        [$holder, $property] = self::clientProperty($entity);
        $property->setValue($holder, $client);
    }

    /**
     * Whether the client of the row was registered when the row was loaded.
     */
    public static function isResolved(Interaction|AuthorizationCode|RefreshToken|Consent $entity): bool
    {
        [$holder, $property] = self::clientProperty($entity);

        return $property->isInitialized($holder);
    }

    /**
     * The object that holds the client and the property that does: the request of an interaction, the
     * row itself otherwise.
     *
     * @return array{object, ReflectionProperty}
     */
    private static function clientProperty(Interaction|AuthorizationCode|RefreshToken|Consent $entity): array
    {
        if ($entity instanceof Interaction) {
            return [$entity->request, new ReflectionProperty(AuthorizationRequest::class, 'client')];
        }

        return [$entity, new ReflectionProperty($entity::class, 'client')];
    }
}
