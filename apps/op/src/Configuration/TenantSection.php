<?php

declare(strict_types=1);

namespace App\Configuration;

use function array_values;
use App\Identity\WiredClaims;
use App\Tenant\TenantFactory;
use Beffroi\Core\Port\AuthenticationPredicatesInterface;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationDeclaredScopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use function is_string;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * The one tenant of this deployment (architecture §5.1): who it says it is, and the "acr" vocabulary it answers in (decision 0010).
 */
final readonly class TenantSection extends ConfigurationSection
{
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
            ->append(self::selfServedClaims())
            ->append(self::authenticationClasses())
            ->append(self::scopes())
            ->end()
            ->end();
    }

    /**
     * The factory of the tenant at runtime, from the slug, the claims and the classes the configuration or the
     * environment names, held to the rules of the tree either way (decision 0030); every other argument is the one of
     * the factory. The slug is held here, where it becomes a tenant: the declarations that name it, the clients, the
     * service providers, belong to a tenant this factory makes.
     *
     * @param mixed $authenticationClasses the classes, as the configuration or the environment carries them
     * @param array<array-key, mixed> $look
     * @param mixed $selfServedClaims the claims, as the configuration or the environment carries them
     *
     * @throws InvalidConfigurationException when the slug is empty, or a list is one the tree refuses
     */
    public static function tenantFactory(
        string $issuer,
        string $slug,
        ?string $name,
        ClockInterface $clock,
        AuthenticationPredicatesInterface $predicates,
        mixed $authenticationClasses = [],
        array $look = [],
        mixed $selfServedClaims = [],
        ?WiredClaims $claims = null,
    ): TenantFactory {
        if ($slug === '') {
            throw new InvalidConfigurationException('The "beffroi" configuration key "tenant.slug" is the stable name of the tenant, and it is empty.');
        }

        return new TenantFactory(
            $issuer,
            $slug,
            $name,
            $clock,
            $predicates,
            self::authenticationClasses()->normalized($authenticationClasses, 'tenant.authentication_classes'),
            $look,
            self::selfServedClaims()->normalized($selfServedClaims, 'tenant.self_served_claims'),
            $claims,
        );
    }

    /**
     * The scopes the tenant hands out tokens for beyond those of its claims at runtime, from the list the configuration
     * or the environment declares, held to the rules of the tree either way (decision 0030).
     *
     * @param mixed $scopes the list, as the configuration or the environment carries it
     *
     * @throws InvalidConfigurationException when the list is one the tree refuses
     * @throws InvalidArgumentException when a scope is no scope token, or is one the tenant does not offer by declaring it
     */
    public static function declaredScopes(string $tenantSlug, mixed $scopes): ConfigurationDeclaredScopes
    {
        /** @var list<string> $declared the tree declares each one a string */
        $declared = array_values(self::scopes()->normalized($scopes, 'tenant.scopes'));

        return new ConfigurationDeclaredScopes($tenantSlug, $declared);
    }

    /**
     * The scopes of the APIs of the tenant, as the tree declares them, which the environment may carry whole.
     */
    private static function scopes(): EnvironmentListDefinition
    {
        $scopes = new EnvironmentListDefinition('scopes');
        $scopes
            ->info('The scopes this tenant hands out tokens for beyond "openid", the scopes of the claims this provider serves and "offline_access" (issue #920): the scopes of the APIs it protects, which stand for no claim. The tenant offers them, its discovery document announces them in "scopes_supported", and a client that registers itself may register them, a registration being held to what the tenant offers (decision 0009). A scope a declared client registers is offered as well, so a deployment that declares its clients may name none here; one that declares none, as the image, has nothing else to make such a scope exist. "offline_access" is never one of them, the wired grants deciding it (OIDC Core section 11): it is refused, as a value that is no scope token (RFC 6749 section 3.3) is, when the service that reads the list is built. None by default.')
            ->stringPrototype()
            ->end()
            ->defaultValue([]);

        return $scopes;
    }

    /**
     * The claims a person may change of themselves, as the tree declares them, which the environment may carry whole.
     */
    private static function selfServedClaims(): EnvironmentListDefinition
    {
        $claims = new EnvironmentListDefinition('self_served_claims');
        $claims
            ->info('The claims the people of this tenant may change of themselves on the page of their account (issue #452), by the names of OIDC Core §5.1. It is a rule of the tenant and never an option of the deployment: a tenant whose directory owns the data opens none, a tenant that creates its people by hand may open all of them, and one instance serves both. Nothing by default, because opening a claim is a decision somebody takes where closing one would be a decision nobody took. A name no claim of this provider answers refuses the start.')
            ->scalarPrototype()
            ->end()
            ->defaultValue([]);

        return $claims;
    }

    /**
     * The "acr" vocabulary of the tenant, as the tree declares it, which the environment may carry whole.
     */
    private static function authenticationClasses(): EnvironmentListDefinition
    {
        $classes = new EnvironmentListDefinition('authentication_classes');
        $classes
            ->info('The "acr" vocabulary of the tenant (decision 0010): class names, in the order a session is answered in, each on a predicate of the provider, by the name that predicate gives itself. The default policy ("phrh", "phr", "2", "1") when nothing is named. The predicates are the ones the deployment is wired with and this tree keeps no list of them beside the wiring: a name none of them carries refuses the start, naming the ones that are wired.')
            ->useAttributeAsKey('name')
            ->normalizeKeys(false)
            ->scalarPrototype()
            ->cannotBeEmpty()
            ->end()
            ->defaultValue([]);

        return $classes;
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $tenant = $this->own($config);
        $services
            ->get(TenantFactory::class)
            ->factory(self::tenantFactory(...))
            ->arg('$issuer', self::string($tenant, 'issuer'))
            ->arg('$slug', self::string($tenant, 'slug'))
            ->arg(
                '$name',
                is_string($tenant['name'] ?? null) ? $tenant['name'] : null,
            )
            ->arg('$authenticationClasses', $tenant['authentication_classes'] ?? [])
            ->arg('$look', self::section($tenant, 'look'))
            ->arg('$selfServedClaims', $tenant['self_served_claims'] ?? []);
        $services->get(ConfigurationDeclaredScopes::class)->factory(self::declaredScopes(...))->arg('$tenantSlug', self::string($tenant, 'slug'))->arg(
            '$scopes',
            $tenant['scopes'] ?? [],
        );
    }
}
