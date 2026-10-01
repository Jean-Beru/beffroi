<?php

declare(strict_types=1);

namespace Heidi\Bundle\Configuration;

use DateInterval;
use Doctrine\DBAL\Connection;
use Heidi\Bundle\Doctrine\PersonalData\EncryptedColumnTypes;
use Heidi\Bundle\Doctrine\PersonalData\TenantDataKeyStores;
use Heidi\Bundle\Doctrine\PersonalData\TenantScopedEncrypter;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Key\FilePairwiseSalt;
use Heidi\Bundle\Key\FileTenantKeyRepository;
use Heidi\Bundle\Key\StagingDelay;
use Heidi\Bundle\Profiler\KmsClient;
use Heidi\Core\Application\Key\TenantKeyRotator;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\DataKeyStore;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\EncryptedTypes;
use Symfony\Component\KeyManagement\Bridge\DoctrineOrm\SchemaListener\DataKeyStoreSchemaListener;
use Symfony\Component\KeyManagement\EnvelopeEncrypter;
use Symfony\Component\KeyManagement\StoredEnvelopeEncrypter;
use Heidi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Heidi\Core\Bridge\KeyManagement\EnvelopeSecretSealer;
use Heidi\Oidc\Application\Discovery\JwksHandler;
use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_locator;
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
            ->info('Directory of the sealed keys, one file per key and per tenant, and of the pairwise salt of each tenant, one file beside them (OIDC Core section 8.1).')
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
        // The columns that carry a personal datum (decisions 0011 and 0018): a data key per tenant and per
        // family of columns, wrapped by the master key of that tenant, the one its signing keys are already
        // sealed under, and a payload that carries a 16-byte reference to it rather than the wrapped key.
        //
        // Three services and no configuration of their own: the table is the bundle's, and what a
        // deployment chooses of the rest it has already chosen above, by naming its KMS and the pattern of
        // its master keys. None of them is tagged "kernel.reset": the component tags its own store with it
        // and "forget()" would put the KMS back on the path of every request that touches a column, where a
        // thread is to keep open what it has opened (decision 0018, 12-garde-des-cles.md §1.5).
        $services->set('heidi.data_keys', TenantDataKeyStores::class)->args([
            service(Connection::class),
            tagged_locator('key_management.client', 'key'),
            self::string($keys, 'kms'),
            self::string($keys, 'key_id'),
            TenantDataKeyStores::TABLE,
        ]);
        // The fallback reads an envelope that carries its own data key rather than refusing it: nothing of
        // this repository has written one into a column, but the sealed keys and the sealed secrets are
        // envelopes of that shape and the same encrypter is what reads them.
        $services->set('heidi.kms.stored_envelopes', StoredEnvelopeEncrypter::class)->args([
            service('heidi.data_keys'),
            service('heidi.kms.envelopes'),
        ]);
        // Lazy, and public so that it stays lazy: the types are registered while the bundles boot, and what
        // they are handed is this encrypter, so building it there would build the store, the connection and
        // the KMS client of every process that boots, for a path a process that seals nothing never takes.
        // A private service with one consumer is inlined, and an inlined service is not a proxy, so being
        // reachable by its name is what keeps the KMS off the path of a boot; it is also what lets a
        // deployment seal a value outside Doctrine. What it costs is asserted rather than trusted
        // (HeidiBundleExtensionTest).
        $services
            ->set('heidi.personal_data.encrypter', TenantScopedEncrypter::class)
            ->public()
            ->lazy()
            ->args([
                service('heidi.kms.stored_envelopes'),
                service(TenantProvider::class),
            ]);
        // What the bundles register while they boot (HeidiBundle::boot()), and the one argument a
        // deployment chooses: which encrypter the types are given is what decides where the data key of a
        // scope comes from.
        $services
            ->set('heidi.encrypted_types', EncryptedTypes::class)
            ->public()
            ->factory(EncryptedColumnTypes::service(...))
            ->args([service('heidi.personal_data.encrypter')]);
        // The table of the store declared in the schema the ORM assembles, so that "doctrine:schema:update"
        // does not offer to drop what no mapping of the bundle puts there. What the listener of the ORM
        // bridge asks for is a DataKeyStore and not the router, so what is tagged is the one store every
        // read goes to: the table of a read is the table of every write.
        $services
            ->set('heidi.data_keys.reader', DataKeyStore::class)
            ->factory([service('heidi.data_keys'), 'reader'])
            ->tag('heidi.data_key_store');
        $services->set(
            'heidi.data_keys.schema_listener',
            DataKeyStoreSchemaListener::class,
        )->args([tagged_iterator('heidi.data_key_store')])->tag('doctrine.event_listener', [
            'event' => 'postGenerateSchema',
        ]);
        $services->get(EnvelopeKeySealer::class)->arg('$envelopes', service('heidi.kms.envelopes'))->arg('$kmsKeyId', self::string($keys, 'key_id'));
        $services->get(EnvelopeSecretSealer::class)->arg('$envelopes', service('heidi.kms.envelopes'))->arg('$kmsKeyId', self::string($keys, 'key_id'));
        $services->get(FileTenantKeyRepository::class)->arg('$directory', self::string($keys, 'storage'));
        // The pairwise salt of a tenant lives beside its sealed keys and is sealed like them (OIDC Core
        // §8.1): one directory to back up, one KMS to lose.
        $services->get(FilePairwiseSalt::class)->arg('$directory', self::string($keys, 'storage'));
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
