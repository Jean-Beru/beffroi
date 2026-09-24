<?php

declare(strict_types=1);

namespace Heidi\Bundle\Configuration;

use DateInterval;
use Heidi\Bundle\Key\FileTenantKeyRepository;
use Heidi\Bundle\Key\StagingDelay;
use Heidi\Bundle\Profiler\KmsClient;
use Heidi\Core\Application\Key\TenantKeyRotator;
use Symfony\Component\KeyManagement\EnvelopeEncrypter;
use Heidi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Heidi\Core\Bridge\KeyManagement\EnvelopeSecretSealer;
use Heidi\Oidc\Application\Discovery\JwksHandler;
use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * Where the keys of the tenant live and what seals them (architecture §3.3): the KMS is named here and built by the framework, and what the bundle holds is that name.
 */
final readonly class KeysSection extends ConfigurationSection
{
    public function name(): string
    {
        return 'keys';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('keys')
            ->info('Where the keys of the tenants live: sealed by the KMS named here, stored as files until a table takes over (architecture §3.3).')
            ->isRequired()
            ->children()
            ->scalarNode('kms')
            ->info('Name of the KMS client that seals the private keys, an entry of "key_management.clients" of the framework configuration (a DSN there, or the members of a composite client); the KMS keeps, it never signs.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('key_id')
            ->info('The key of that KMS the keys of the tenants are sealed under (backend-specific: the id of a sodium key, a Vault transit key name, an ARN); "{tenant}" stands for the slug of the tenant, one master key each.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('storage')
            ->info('Directory of the sealed keys, one file per key and per tenant.')
            ->defaultValue('%kernel.project_dir%/var/keys')
            ->cannotBeEmpty()
            ->end()
            ->integerNode('jwks_max_age')
            ->info('How long a relying party may cache the JWK Set, in seconds (RFC 7517 §5, architecture §4.8); the staging window of a rotation derives from it, so that the two cannot drift apart (§3.3).')
            ->defaultValue(JwksHandler::DEFAULT_MAX_AGE)
            ->min(0)
            ->end()
            ->integerNode('staging_delay')
            ->info('How long a new key is published before it signs, in seconds (architecture §3.3, §9); unless set, jwks_max_age plus the 60 s refetch cooldown of oidc_login: the max-age is what a relying party with a warm cache needs to see the new key, the cooldown what one served by a shared HTTP cache needs to refetch it.')
            ->defaultNull()
            ->min(0)
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $keys = $this->own($config);
        // the client is named here and built there: the KMS clients live in "key_management.clients" of
        // the framework configuration, which is also where a client made of several providers and a data
        // key store are declared, and where a DSN that may carry key material already belongs. What the
        // bundle holds is a name, and an alias to the client that name points at.
        $services->alias('heidi.kms', 'key_management.' . self::string($keys, 'kms'));
        $services->set('heidi.kms.envelopes', EnvelopeEncrypter::class)->args([service('heidi.kms')]);
        $services->get(EnvelopeKeySealer::class)->arg('$envelopes', service('heidi.kms.envelopes'))->arg('$kmsKeyId', self::string($keys, 'key_id'));
        $services->get(EnvelopeSecretSealer::class)->arg('$envelopes', service('heidi.kms.envelopes'))->arg('$kmsKeyId', self::string($keys, 'key_id'));
        $services->get(FileTenantKeyRepository::class)->arg('$directory', self::string($keys, 'storage'));
        if ($debug) {
            $services->get(KmsClient::class)->arg('$name', self::string($keys, 'kms'));
        }
        $services->get(JwksHandler::class)->arg('$maxAge', self::integer($keys, 'jwks_max_age'));
        // derived at runtime, once the environment placeholders are numbers
        $services->get(TenantKeyRotator::class)->arg('$stagingDelay', inline_service(DateInterval::class)
            ->factory(StagingDelay::interval(...))
            ->args([isset($keys['staging_delay']) ? self::integer($keys, 'staging_delay') : null, self::integer($keys, 'jwks_max_age')]));
    }
}
