<?php

declare(strict_types=1);

namespace App\Saml;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Bridge\Model\ModelEntityId;
use Beffroi\Saml\Domain\Metadata\ServiceProviderEndpoints;
use Beffroi\Saml\Port\IdentityProviderEndpointsInterface;
use Beffroi\Saml\Port\ServiceProviderEndpointsInterface;
use LogicException;
use function sprintf;
use function strtr;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * The endpoints of the SAML service provider of a tenant under the origin of its issuer, never under the Host header
 * of a request (spec/saml.md S-39, section 6.9 step 3), as RouterIdentityProviderEndpoints locates those of its
 * identity provider, and the entity ID it goes by (S-38).
 *
 * The path of the metadata and the one of the assertion consumer service are the router's, each compared with the one
 * the issuer makes a reader expect: routes mounted elsewhere are refused at the first request. The route of the
 * assertion consumer service is the one statement of where it answers (S-39, S-52): its URL is generated, never its
 * path written again beside the route. The entity ID is the URL of the metadata unless the deployment names another, a URI of M-6
 * that is never the one of the identity provider of the tenant: ServiceProviderEntityIdPass refuses another when the
 * container is compiled, and this refuses it again at the first use, should the issuer or the entity ID hold an
 * environment variable.
 *
 * It writes as well the URL of the metadata given to one upstream identity provider (S-65), the one an operator hands
 * that provider, which no request asks for when a command prints it: the origin of the issuer is the only one it has.
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
        $metadata = $this->underTheIssuer(
            $tenant,
            ServiceProviderRoutes::METADATA,
            ServiceProviderRoutes::METADATA_PATH,
            'The SAML metadata of the service provider',
        );
        $endpoints = new ServiceProviderEndpoints(
            $this->entityId === null ? $metadata : ModelEntityId::read($this->entityId),
            $metadata,
            $this->underTheIssuer(
                $tenant,
                ServiceProviderRoutes::ASSERTION_CONSUMER_SERVICE,
                ServiceProviderRoutes::ASSERTION_CONSUMER_SERVICE_PATH,
                'The assertion consumer service of the service provider',
            ),
        );
        ServiceProviderEndpoints::assertOwnEntityId($endpoints->entityId, $this->identityProvider->locate($tenant)->metadata);

        return $endpoints;
    }

    /**
     * The URL of the metadata given to that upstream identity provider (spec/saml.md S-65), its last segment the entity
     * ID in base64url (IdentityProviderSegment), under the origin of the issuer.
     *
     * @throws LogicException when the routes of the provider are not mounted under the path of the issuer
     */
    public function metadataFor(Tenant $tenant, string $identityProvider): string
    {
        $segment = IdentityProviderSegment::of($identityProvider);

        return $this->underTheIssuer(
            $tenant,
            ServiceProviderRoutes::METADATA_FOR_IDENTITY_PROVIDER,
            strtr(ServiceProviderRoutes::METADATA_FOR_IDENTITY_PROVIDER_PATH, [
                '{identityProvider}' => $segment,
            ]),
            sprintf('The SAML metadata given to the identity provider "%s"', $identityProvider),
            [
                'identityProvider' => $segment,
            ],
        );
    }

    /**
     * The URL the router generates for a route under the origin of the issuer, refused unless it is the one the issuer
     * makes a reader expect.
     *
     * @param string                $path       the path the issuer makes a reader expect under it, its parameters written
     * @param array<string, string> $parameters the parameters of the route
     *
     * @throws LogicException when the routes of the provider are not mounted under the path of the issuer
     */
    private function underTheIssuer(Tenant $tenant, string $route, string $path, string $what, array $parameters = []): string
    {
        $generated = $tenant->issuer->origin() . $this->router->generate($route, $parameters, UrlGeneratorInterface::ABSOLUTE_PATH);
        $expected = $tenant->issuer->value . $path;
        if ($generated !== $expected) {
            throw new LogicException(sprintf(
                '%s is served at "%s" but the issuer "%s" puts it under "%s": mount the routes of the provider under the path of the issuer.',
                $what,
                $generated,
                $tenant->issuer->value,
                $expected,
            ));
        }

        return $generated;
    }
}
