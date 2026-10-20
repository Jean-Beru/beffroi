<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Bundle\Key\DormantKeyAlgorithms;
use Beffroi\Bundle\Saml\JoseSamlSigningAlgorithms;
use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Saml\Application\Metadata\IdentityProviderMetadataHandler;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * Whether the tenant of this deployment is a SAML identity provider (beffroi/saml, spec/saml.md section 6.1), and
 * whether it wants the requests it receives signed.
 *
 * A deployment that does not enable it wires nothing: the tenant draws no SAML key, and the route of the metadata
 * answers that there is none. The algorithm is left dormant instead, so that a key the tenant drew before the
 * deployment turned it off stays in the key directory, read by nothing, and the other keys go on without it. Enabled,
 * the algorithm of the SAML signing key is wired with the others, so that the key commands draw, list and rotate it,
 * and the scheduled step stages its successors, as every key of the tenant.
 */
final readonly class SamlSection extends ConfigurationSection
{
    public function name(): string
    {
        return 'saml';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('saml')
            ->info('SAML 2.0 (beffroi/saml, decision 0013): the roles the tenant of this deployment plays.')
            ->addDefaultsIfNotSet()
            ->children()
            ->arrayNode('identity_provider')
            ->info('The tenant as a SAML identity provider (spec/saml.md section 6.1). Disabled, nothing of it is wired: the tenant draws no SAML key and serves no metadata. Enabled, its key is drawn with "beffroi:keys:generate --algorithm=SAML-SIGNING" and rotates as every key of the tenant.')
            ->canBeEnabled()
            ->children()
            ->booleanNode('want_authn_requests_signed')
            ->info('What the metadata says in WantAuthnRequestsSigned (SAML Metadata section 2.4.3): true asks every service provider to sign its requests, which is what a broker configured from the metadata does (spec/model.md section 6.9). Turned off, the requests of service providers that cannot sign are accepted where their configuration says so, and the logout of a broker that signs only when asked is lost.')
            ->defaultTrue()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $identityProvider = self::section($this->own($config), 'identity_provider');
        if (($identityProvider['enabled'] ?? false) !== true) {
            $services->get(SamlSigning::class)->tag(DormantKeyAlgorithms::TAG);

            return;
        }
        $services->get(SamlSigning::class)->tag(JoseSamlSigningAlgorithms::TAG);
        $services->get(IdentityProviderMetadataHandler::class)->arg('$wantAuthnRequestsSigned', self::boolean(
            $identityProvider,
            'want_authn_requests_signed',
        ))->arg('$maxAge', self::integer(self::section($config, 'keys'), 'jwks_max_age'));
    }
}
