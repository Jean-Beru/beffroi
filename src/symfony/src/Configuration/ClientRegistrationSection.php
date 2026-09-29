<?php

declare(strict_types=1);

namespace Heidi\Bundle\Configuration;

use Heidi\Bundle\Client\SectorIdentifierDocumentFetcher;
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
    /**
     * The two durations of decision 0009 as the tree writes them, in seconds; a test checks they are the
     * ones the policy of the module defaults to, so that the reference a deployment reads and the default a
     * deployment gets cannot say different things.
     */
    public const int DEFAULT_KEEP_A_CLIENT_UNUSED_FOR = 7_776_000;

    public const int DEFAULT_KEEP_A_CLIENT_NEVER_USED_FOR = 604_800;

    /**
     * What one read of a sector identifier document is given (OIDC Registration §5), the same numbers one
     * read of a "jwks_uri" is given: a client that hangs must not hold a worker, and a registration is
     * waiting on this one.
     */
    public const float DEFAULT_SECTOR_IDENTIFIER_TIMEOUT = 3.0;

    public const int DEFAULT_SECTOR_IDENTIFIER_MAX_SIZE = 65536;

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
            ->info('What authorises a registration, by the name the class that is that mode gives itself. This provider is wired with "initial_access_token", a credential the tenant issues, names, limits in number and duration and revokes (RFC 7591 section 1.2), and with "open", which registers whoever asks with no credential at all (RFC 7591 section 1.3) and is written by a tenant that has no real user. Left out, the tenant has no registration endpoint at all: it is not a mode of refusing, it is the absence of the endpoint. It is named per tenant and nothing here opens a mode for more than the tenant that names it.')
            ->defaultNull()
            ->end()
            ->integerNode('keep_a_client_unused_for')
            ->info('Seconds a client that was used may go without being used again before it is deleted (decision 0009). Ninety days by default, which is the absolute lifetime of a refresh token family this provider is configured with by default: past it, nothing that client was ever issued can still be presented, so deleting it takes nothing away from anybody.')
            ->defaultValue(self::DEFAULT_KEEP_A_CLIENT_UNUSED_FOR)
            ->min(1)
            ->end()
            ->integerNode('keep_a_client_never_used_for')
            ->info('Seconds a client that was never used lives at all (decision 0009). Seven days by default, a working week, so that a registration made on a Friday afternoon is still there the next Friday; a client that was never used holds nothing, so the only question is how long whoever registered it may take to make its first request. The mode that registers strangers makes it the shorter of the two.')
            ->defaultValue(self::DEFAULT_KEEP_A_CLIENT_NEVER_USED_FOR)
            ->min(1)
            ->end()
            ->floatNode('sector_identifier_timeout')
            ->info('Seconds one read of a sector_identifier_uri is given, connection included (OIDC Registration section 5). It is read once, when a client registers or replaces itself, and the registration waits for it.')
            ->defaultValue(self::DEFAULT_SECTOR_IDENTIFIER_TIMEOUT)
            ->min(0.1)
            ->end()
            ->integerNode('sector_identifier_max_size')
            ->info('Bytes a sector_identifier_uri may answer before the read stops; the document is the JSON array of the redirection URIs of the clients of one sector.')
            ->defaultValue(self::DEFAULT_SECTOR_IDENTIFIER_MAX_SIZE)
            ->min(1)
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
        $services
            ->get(ConfigurationClientRegistrationPolicy::class)
            ->arg('$tenantSlug', self::string(self::section($config, 'tenant'), 'slug'))
            ->arg(
                '$mode',
                is_string($mode) ? $mode : null,
            )
            ->arg('$exemptsConfidentialClientsFromPkce', self::boolean($registration, 'exempt_confidential_clients_from_pkce'))
            ->arg(
                '$keepsAClientUnusedFor',
                self::seconds($registration, 'keep_a_client_unused_for'),
            )
            ->arg('$keepsAClientNeverUsedFor', self::seconds($registration, 'keep_a_client_never_used_for'));
        $services->get(SectorIdentifierDocumentFetcher::class)->arg('$timeout', self::float(
            $registration,
            'sector_identifier_timeout',
        ))->arg('$maximumSize', self::integer($registration, 'sector_identifier_max_size'));
    }
}
