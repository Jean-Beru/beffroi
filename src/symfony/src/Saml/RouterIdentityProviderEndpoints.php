<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Metadata\IdentityProviderEndpoints;
use Beffroi\Saml\Port\IdentityProviderEndpointsInterface;
use LogicException;
use function sprintf;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * The endpoints of the SAML identity provider of a tenant under the origin of its issuer, never under the Host header
 * of a request (spec/saml.md section 6.1 step 3, S-4), as RouterEndpointLocator locates those of the provider.
 *
 * The path of the metadata is the router's, compared with the one the issuer makes a reader expect: routes mounted
 * elsewhere are refused at the first request. The single sign-on service is the router's too, under the same prefix
 * (issue #731); the single logout service is at the path of IdentityProviderRoutes until the stories that serve it
 * route it (issues #734 and #735).
 */
final readonly class RouterIdentityProviderEndpoints implements IdentityProviderEndpointsInterface
{
    public function __construct(
        private UrlGeneratorInterface $router,
    ) {
    }

    public function locate(Tenant $tenant): IdentityProviderEndpoints
    {
        $issuer = $tenant->issuer->value;
        $metadata = $tenant->issuer->origin() . $this->router->generate(IdentityProviderRoutes::METADATA, [], UrlGeneratorInterface::ABSOLUTE_PATH);
        $expected = $issuer . IdentityProviderRoutes::METADATA_PATH;
        if ($metadata !== $expected) {
            throw new LogicException(sprintf(
                'The SAML metadata is served at "%s" but the issuer "%s" puts the identity provider under "%s": mount the routes of the bundle under the path of the issuer.',
                $metadata,
                $issuer,
                $expected,
            ));
        }

        return new IdentityProviderEndpoints(
            $metadata,
            $tenant->issuer->origin() . $this->router->generate(IdentityProviderRoutes::SINGLE_SIGN_ON, [], UrlGeneratorInterface::ABSOLUTE_PATH),
            $issuer . IdentityProviderRoutes::SINGLE_LOGOUT_PATH,
        );
    }
}
