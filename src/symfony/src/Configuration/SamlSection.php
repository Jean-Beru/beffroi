<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Bundle\Key\DormantKeyAlgorithms;
use Beffroi\Bundle\Saml\JoseSamlSigningAlgorithms;
use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Saml\Application\Metadata\IdentityProviderMetadataHandler;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use function is_array;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * Whether the tenant of this deployment is a SAML identity provider (beffroi/saml, spec/saml.md section 6.1), whether
 * it wants the requests it receives signed, and the service providers it serves (section 5.2).
 *
 * A deployment that does not enable it wires nothing: the tenant draws no SAML key, and the route of the metadata
 * answers that there is none. The algorithm is left dormant instead, so that a key the tenant drew before the
 * deployment turned it off stays in the key directory, read by nothing, and the other keys go on without it. Enabled,
 * the algorithm of the SAML signing key is wired with the others, so that the key commands draw, list and rotate it,
 * and the scheduled step stages its successors, as every key of the tenant.
 *
 * The service providers are declared here and nowhere else, as the clients are (S-5): no request registers one and no
 * page edits one. A declaration is validated when the container is compiled (ServiceProvidersPass); its metadata are
 * read by "beffroi:saml:service-provider:refresh" and by the hourly step of the schedule, and kept in the database.
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
            ->arrayNode('service_providers')
            ->info('The service providers of the tenant, keyed by entity ID, compared exactly with the one of their metadata (spec/saml.md S-5). Their metadata are read by "beffroi:saml:service-provider:refresh" and every hour after, refused when expired, older than the document accepted, or without a key for encryption where the declaration asks for encryption (S-6, S-7). Declared only for a tenant that is an identity provider.')
            ->useAttributeAsKey('entity_id')
            ->normalizeKeys(false)
            ->arrayPrototype()
            ->children()
            ->scalarNode('metadata')
            ->info('Where the metadata are read from: an https URL, fetched without following a redirect, or the absolute path of a file of the deployment. Nothing else, a plain http URL included. The channel is what vouches for them unless metadata_signers pins who signs them.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->arrayNode('metadata_signers')
            ->info('The certificates the metadata are signed by, each the base64 of its DER as an X509Certificate carries it, sixteen at most: the metadata are then verified under them and carry a validUntil (spec/saml.md S-5, S-6). Left empty, they are trusted by the channel they come through.')
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('attributes')
            ->info('The claims of the provider sent to this service provider, keyed by the name of the SAML attribute each one is sent as (Core section 2.7.3.1), 256 at most. A claim may be sent under several names.')
            ->useAttributeAsKey('name')
            ->normalizeKeys(false)
            ->arrayPrototype()
            ->children()
            ->scalarNode('claim')
            ->info('The name of the claim, as the provider names it (OIDC Core section 5.1).')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->enumNode('name_format')
            ->info('The name format of the attribute (Core section 8.2): "uri", the default the SAML V2.0 interoperability profiles ask for, under which the name is an absolute URI; "basic"; or "unspecified".')
            ->values(['uri', 'basic', 'unspecified'])
            ->defaultValue('uri')
            ->end()
            ->scalarNode('friendly_name')
            ->info('A name a person reads (Core section 2.7.3.1), which nothing compares.')
            ->defaultNull()
            ->end()
            ->end()
            ->end()
            ->end()
            ->booleanNode('encrypt_assertions')
            ->info('The assertions of this service provider are encrypted to a key of its metadata, which must then hold one for encryption, or the metadata are refused (spec/saml.md S-7).')
            ->defaultFalse()
            ->end()
            ->booleanNode('signs_authn_requests')
            ->info('This service provider signs its authentication requests. Turned off for one that cannot, Entra among them, whose unsigned requests are then the only ones accepted (issue #730); there is no switch for the tenant or for the deployment.')
            ->defaultTrue()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end()
            ->validate()
            ->ifTrue(self::declaresServiceProvidersAlone(...))
            ->thenInvalid('Service providers are declared for a tenant that is a SAML identity provider: enable "beffroi.saml.identity_provider", or remove "beffroi.saml.service_providers".')
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $services->get(ConfigurationServiceProviders::class)->arg('$tenantSlug', self::string(self::section($config, 'tenant'), 'slug'))->arg(
            '$definitions',
            self::section($this->own($config), 'service_providers'),
        );
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

    /**
     * Whether service providers are declared for a tenant that is no identity provider, which serves none of them.
     */
    private static function declaresServiceProvidersAlone(mixed $saml): bool
    {
        if (! is_array($saml)) {
            return false;
        }

        return self::section($saml, 'service_providers') !== [] && (self::section($saml, 'identity_provider')['enabled'] ?? false) !== true;
    }
}
