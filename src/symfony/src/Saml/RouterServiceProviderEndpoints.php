<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Bridge\Model\ModelEntityId;
use Beffroi\Saml\Domain\Metadata\ServiceProviderEndpoints;
use Beffroi\Saml\Port\IdentityProviderEndpointsInterface;
use Beffroi\Saml\Port\ServiceProviderEndpointsInterface;
use LogicException;
use function sprintf;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * The endpoints of the SAML service provider of a tenant under the origin of its issuer, never under the Host header
 * of a request (spec/saml.md S-39, section 6.9 step 3), as RouterIdentityProviderEndpoints locates those of its
 * identity provider, and the entity ID it goes by (S-38).
 *
 * The path of the metadata is the router's, compared with the one the issuer makes a reader expect: routes mounted
 * elsewhere are refused at the first request. The assertion consumer service is the issuer and the path of its route
 * until issue #784 routes it. The entity ID is the URL of the metadata unless the deployment names another, a URI of M-6
 * that is never the one of the identity provider of the tenant: ServiceProviderEntityIdPass refuses another when the
 * container is compiled, and this refuses it again at the first use, should the issuer or the entity ID hold an
 * environment variable.
 */
final readonly class RouterServiceProviderEndpoints implements ServiceProviderEndpointsInterface
{
    /**
     * @param string|null $entityId the entity ID the deployment names, the URL of the metadata when null (S-38)
     */
    public function __construct(
        private UrlGeneratorInterface $router,
        private IdentityProviderEndpointsInterface $identityProvider,
        private ?string $entityId = null,
    ) {
    }

    public function locate(Tenant $tenant): ServiceProviderEndpoints
    {
        $issuer = $tenant->issuer->value;
        $metadata = $tenant->issuer->origin() . $this->router->generate(ServiceProviderRoutes::METADATA, [], UrlGeneratorInterface::ABSOLUTE_PATH);
        $expected = $issuer . ServiceProviderRoutes::METADATA_PATH;
        if ($metadata !== $expected) {
            throw new LogicException(sprintf(
                'The SAML metadata of the service provider is served at "%s" but the issuer "%s" puts it under "%s": mount the routes of the bundle under the path of the issuer.',
                $metadata,
                $issuer,
                $expected,
            ));
        }
        $endpoints = new ServiceProviderEndpoints(
            $this->entityId === null ? $metadata : ModelEntityId::read($this->entityId),
            $metadata,
            $issuer . ServiceProviderRoutes::ASSERTION_CONSUMER_SERVICE_PATH,
        );
        ServiceProviderEndpoints::assertOwnEntityId($endpoints->entityId, $this->identityProvider->locate($tenant)->metadata);

        return $endpoints;
    }
}
