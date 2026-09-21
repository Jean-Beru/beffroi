<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Listener;

use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\AuthorizationRequest;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRequest;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Domain\Token\StoredAccessToken;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use ReflectionProperty;

/**
 * Resolves the client of a loaded row from its "client_id" (architecture §4.1), set by reflection like the
 * other readonly properties. A client no longer registered leaves the property uninitialised; the
 * repositories ask isResolved() and treat the row as absent.
 */
final readonly class ClientResolver
{
    public function __construct(
        private ClientRepositoryInterface $clients,
    ) {
    }

    public function postLoad(Interaction|AuthorizationCode|PushedAuthorizationRequest|RefreshToken|StoredAccessToken|Consent $entity): void
    {
        $client = $this->clients->findByClientId($entity->tenant, $entity->clientId);
        if ($client === null) {
            return;
        }
        [$holder, $property] = self::clientProperty($entity);
        $property->setValue($holder, $client);
    }

    public static function isResolved(Interaction|AuthorizationCode|PushedAuthorizationRequest|RefreshToken|StoredAccessToken|Consent $entity): bool
    {
        [$holder, $property] = self::clientProperty($entity);

        return $property->isInitialized($holder);
    }

    /**
     * @return array{object, ReflectionProperty} the holder of the client and the property
     */
    private static function clientProperty(Interaction|AuthorizationCode|PushedAuthorizationRequest|RefreshToken|StoredAccessToken|Consent $entity): array
    {
        if ($entity instanceof Interaction) {
            return [$entity->request, new ReflectionProperty(AuthorizationRequest::class, 'client')];
        }

        return [$entity, new ReflectionProperty($entity::class, 'client')];
    }
}
