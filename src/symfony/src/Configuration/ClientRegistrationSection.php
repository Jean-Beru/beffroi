<?php

declare(strict_types=1);

namespace Heidi\Bundle\Configuration;

use Heidi\Oidc\Bridge\Configuration\ConfigurationClientRegistrationPolicy;
use function is_string;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * What the tenant does with a client that registers itself (RFC 7591, decision 0009). A deployment that
 * writes nothing here registers nobody: closed is the default, and a closed tenant has no
 * "registration_endpoint" in its document and none on the wire.
 */
final readonly class ClientRegistrationSection extends ConfigurationSection
{
    public function name(): string
    {
        return 'client_registration';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('client_registration')
            ->info('How a client that nobody declared comes to exist here (RFC 7591, decision 0009). Absent, the tenant registers nobody, which is the default and what a deployment that writes nothing gets.')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('mode')
            ->info('What authorises a registration, by the name the class that is that mode gives itself; "initial_access_token" is the one this provider is wired with. Left out, the tenant has no registration endpoint at all: it is not a mode of refusing, it is the absence of the endpoint.')
            ->defaultNull()
            ->end()
            ->booleanNode('exempt_confidential_clients_from_pkce')
            ->info('The named exception of decision 0017, for the tenant that writes it and no other: the confidential clients this policy registers are registered without the PKCE requirement, because the Dynamic OP profile of OIDC Core sends no code_challenge and offers no way to. A public client is never exempted whatever this says, "plain" never exists, and a code_challenge a client does send is verified like any other. Write it with the reason a tenant has for it beside it; a tenant with real users has none.')
            ->defaultFalse()
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $registration = $this->own($config);
        $mode = $registration['mode'] ?? null;
        $services->get(ConfigurationClientRegistrationPolicy::class)->arg('$tenantSlug', self::string(self::section($config, 'tenant'), 'slug'))->arg(
            '$mode',
            is_string($mode) ? $mode : null,
        )->arg('$exemptsConfidentialClientsFromPkce', self::boolean($registration, 'exempt_confidential_clients_from_pkce'));
    }
}
