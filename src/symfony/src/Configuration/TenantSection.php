<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Bundle\Tenant\TenantFactory;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationPredicate;
use function array_column;
use function is_string;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * The one tenant of this deployment (architecture §5.1): who it says it is, and the "acr" vocabulary it answers in (decision 0010).
 */
final readonly class TenantSection extends ConfigurationSection
{
    /**
     * The default policy of decision 0010, restated for the same reason; a test checks it equals the core's.
     */
    public const array DEFAULT_AUTHENTICATION_CLASSES = [
        AuthenticationContextClass::PHISHING_RESISTANT_HARDWARE => AuthenticationPredicate::PhishingResistantHardware->value,
        AuthenticationContextClass::PHISHING_RESISTANT => AuthenticationPredicate::PhishingResistant->value,
        AuthenticationContextClass::TWO_FACTORS => AuthenticationPredicate::TwoFactors->value,
        AuthenticationContextClass::SINGLE_FACTOR => AuthenticationPredicate::SingleFactor->value,
    ];

    public function name(): string
    {
        return 'tenant';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('tenant')
            ->info('The one tenant of this deployment: the key is already a tenant, a table comes later.')
            ->isRequired()
            ->children()
            ->scalarNode('issuer')
            ->info('Issuer identifier (OIDC Discovery §3): an absolute HTTPS URL, no query, no fragment, no trailing slash; plain HTTP on a loopback host only.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('slug')
            ->info('Stable name of the tenant, from which its identifier is derived; renaming it is creating another tenant.')
            ->defaultValue('default')
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('name')
            ->info('Display name; the host of the issuer when absent.')
            ->defaultNull()
            ->end()
            ->arrayNode('look')
            ->info('What this tenant shows of itself on every page of its provider besides its name (issue #449). A deployment that declares none of it is served the pages it has always been served.')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('logo_uri')
            ->info('Where the logo of the tenant is served from: an absolute HTTPS URL, no fragment, no credentials; plain HTTP on a loopback host only. The browser of the visitor loads it, never the provider, and the pages name its origin in their Content-Security-Policy.')
            ->defaultNull()
            ->end()
            ->scalarNode('primary_color')
            ->info('The colour the buttons and the links of the pages are drawn in: three or six hexadecimal digits behind a hash, as "#1b4b8f". It needs "primary_content_color", a colour being unusable without the colour of what is written on it.')
            ->defaultNull()
            ->end()
            ->scalarNode('primary_content_color')
            ->info('The colour of what is written on "primary_color", the two being declared together or not at all.')
            ->defaultNull()
            ->end()
            ->end()
            ->end()
            ->arrayNode('authentication_classes')
            ->info('The "acr" vocabulary of the tenant (decision 0010): class names, in the order a session is answered in, each on a predicate of the provider; the default policy ("phrh", "phr", "2", "1") when absent.')
            ->useAttributeAsKey('name')
            ->normalizeKeys(false)
            ->defaultValue(self::DEFAULT_AUTHENTICATION_CLASSES)
            ->enumPrototype()
            ->values(array_column(AuthenticationPredicate::cases(), 'value'))
            ->end()
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $tenant = $this->own($config);
        $services
            ->get(TenantFactory::class)
            ->arg('$issuer', self::string($tenant, 'issuer'))
            ->arg('$slug', self::string($tenant, 'slug'))
            ->arg(
                '$name',
                is_string($tenant['name'] ?? null) ? $tenant['name'] : null,
            )
            ->arg('$authenticationClasses', self::section($tenant, 'authentication_classes'))
            ->arg('$look', self::section($tenant, 'look'));
    }
}
