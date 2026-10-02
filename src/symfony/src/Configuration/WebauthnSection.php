<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Bundle\Webauthn\FileMetadataBlobStore;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * What the passkeys of the deployment are judged against (architecture §3.5): the metadata blob of the FIDO Alliance, kept where this says.
 */
final readonly class WebauthnSection extends ConfigurationSection
{
    public function name(): string
    {
        return 'webauthn';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('webauthn')
            ->info('What the passkey ceremonies read besides the tenant (architecture §3.4).')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('metadata_storage')
            ->info('Directory of the FIDO metadata the ceremonies check an attestation against: the documents "beffroi:webauthn:mds-refresh" verified and "beffroi:webauthn:mds-import" stored, next to the keys; empty until one of them ran, which the enrolment of the provider does not need.')
            ->defaultValue('%kernel.project_dir%/var/webauthn')
            ->cannotBeEmpty()
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $services->get(FileMetadataBlobStore::class)->arg('$directory', self::string($this->own($config), 'metadata_storage'));
    }
}
