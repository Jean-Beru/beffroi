<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Bundle\Key\DormantKeyAlgorithms;
use Beffroi\Bundle\Saml\JoseSamlSigningAlgorithms;
use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Application\Metadata\IdentityProviderMetadataHandler;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;
use Beffroi\Saml\Domain\Metadata\PublishedMetadata;
use function is_array;
use function is_int;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
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
 * page edits one. A declaration is validated when the container is compiled (ServiceProvidersPass), the claim of a
 * mapping right after, in the same build (MappedClaimsWarmer), and one holding an environment variable at its first
 * use; its metadata are read by "beffroi:saml:service-provider:refresh" and by the hourly step of the schedule, and kept
 * in the database.
 *
 * The keys of the identity provider are a family of their own (spec/saml.md S-12, issue #738): their staging delay and their age are set here,
 * counted in days by default, and not by "beffroi.keys", whose figures suit a JWK Set refetched within minutes. The
 * schedule of the family is built whether the role is enabled or not, the registry of the SAML keys being wired in
 * both cases, empty in the second; the cacheDuration of the metadata is refused here, when the configuration is read,
 * unless it is shorter than the staging delay.
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
            ->info('The tenant as a SAML identity provider (spec/saml.md section 6.1). Disabled, nothing of it is wired: the tenant draws no SAML key and serves no metadata. Enabled, its key is drawn with "beffroi:keys:generate --algorithm=SAML-SIGNING" and rotates as every key of the tenant, by the figures of its own family below.')
            ->canBeEnabled()
            ->children()
            ->booleanNode('want_authn_requests_signed')
            ->info('What the metadata says in WantAuthnRequestsSigned (SAML Metadata section 2.4.3): true asks every service provider to sign its requests, which is what a broker configured from the metadata does (spec/model.md section 6.9). Turned off, the requests of service providers that cannot sign are accepted where their configuration says so, and the logout of a broker that signs only when asked is lost.')
            ->defaultTrue()
            ->end()
            ->integerNode('staging_delay')
            ->info('How long a new SAML signing key is published in the metadata before it signs, in seconds (spec/saml.md S-12, section 7): seven days by default, seven times the cacheDuration of the metadata, so that a service provider whose refresh fails a few times still fetches the next certificate before it is used, and a calendar week for an administrator of a service provider that holds an uploaded certificate (Entra without the metadata URL it may be given, or one Microsoft cannot reach) to put the next one in place; AD FS, in the sample of its documentation, gives its partners five days. The keys of every other family keep "keys.staging_delay".')
            ->defaultValue(SamlSigningAlgorithmInterface::STAGING_DELAY)
            ->min(0)
            ->end()
            ->integerNode('age')
            ->info('How long a SAML signing key works before the planning stages a successor for it, in seconds, counted from its activation (spec/saml.md S-12, section 7): 365 days by default, every rotation being a step for whoever pinned its certificate, and inside the one to three years NIST SP 800-57 Part 1 Rev. 5 §5.3.6 gives a private signature key. The keys of every other family keep "keys.age".')
            ->defaultValue(SamlSigningAlgorithmInterface::AGE)
            ->min(1)
            ->end()
            ->integerNode('cache_duration')
            ->info('How long a service provider may keep the metadata before it fetches it again, in seconds, written as its cacheDuration (SAML Metadata section 2.3.2, spec/saml.md S-12): one day by default, how often SimpleSAMLphp\'s metarefresh and a Shibboleth SP refresh it, and strictly shorter than "staging_delay", which the configuration refuses otherwise.')
            ->defaultValue(IdentityProviderMetadataHandler::DEFAULT_CACHE_DURATION)
            ->min(1)
            ->end()
            ->end()
            ->validate()
            ->always(static function (array $identityProvider): array {
                $cacheDuration = $identityProvider['cache_duration'] ?? null;
                $stagingDelay = $identityProvider['staging_delay'] ?? null;
                // an environment placeholder is a number at runtime only, where the handler checks it again
                if (is_int($cacheDuration) && is_int($stagingDelay)) {
                    try {
                        PublishedMetadata::assertCacheDuration($cacheDuration, $stagingDelay);
                    } catch (InvalidArgumentException $refusal) {
                        throw new InvalidConfigurationException($refusal->getMessage(), 0, $refusal);
                    }
                }

                return $identityProvider;
            })
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
            ->info('This service provider signs its authentication requests. Turned off for one that cannot, Entra among them, whose unsigned requests are then the only ones accepted (issue #730); a provider that signs is refused while its metadata hold no key for signing (S-11); there is no switch for the tenant or for the deployment.')
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
        // the family of the SAML keys exists in every deployment (JoseKeyAlgorithms), so its schedule does too
        $services->set('beffroi.saml.rotation_schedule', RotationSchedule::class)->args([
            self::seconds($identityProvider, 'staging_delay'),
            self::seconds($identityProvider, 'age'),
        ]);
        if (($identityProvider['enabled'] ?? false) !== true) {
            $services->get(SamlSigning::class)->tag(DormantKeyAlgorithms::TAG);

            return;
        }
        $services->get(SamlSigning::class)->tag(JoseSamlSigningAlgorithms::TAG);
        $services->get(IdentityProviderMetadataHandler::class)->arg('$wantAuthnRequestsSigned', self::boolean(
            $identityProvider,
            'want_authn_requests_signed',
        ))->arg('$maxAge', self::integer(self::section($config, 'keys'), 'jwks_max_age'))->arg('$cacheDuration', self::integer(
            $identityProvider,
            'cache_duration',
        ))->arg('$stagingDelay', self::integer($identityProvider, 'staging_delay'));
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
