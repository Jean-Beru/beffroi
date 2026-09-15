<?php

declare(strict_types=1);

namespace Heidi\Bundle;

use function array_column;
use DateInterval;
use Heidi\Bundle\Key\FileSigningKeyRepository;
use Heidi\Bundle\Plane\Plane;
use Heidi\Bundle\Tenant\TenantFactory;
use Heidi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Oidc\Application\Authorization\AuthorizationHandler;
use Heidi\Oidc\Application\Token\AuthorizationCodeGrant;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;
use Heidi\Oidc\Application\Token\TokenIssuer;
use Heidi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use function is_array;
use function is_int;
use function is_string;
use function sprintf;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Kernel\AbstractBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Symfony\Component\KeyManagement\EncrypterInterface;
use Symfony\Component\KeyManagement\EnvelopeEncrypter;

/**
 * The configuration of architecture §5.1, and nothing that decision 0006 forbids: no "insecure_*" key, no
 * compatibility switch, no way to turn PKCE, the exact redirect URI match or the "iss" parameter off. An
 * option that does not exist cannot be copied from a tutorial.
 */
final class HeidiBundle extends AbstractBundle
{
    /**
     * RFC 6749 §4.1.2: "A maximum authorization code lifetime of 10 minutes is RECOMMENDED". The bundle
     * makes the recommendation a bound.
     */
    public const int MAX_AUTHORIZATION_CODE_TTL = 600;

    /**
     * The default the module applies when a client declares nothing; restated here because the
     * configuration tree cannot tell an absent list from an empty one.
     */
    public const array DEFAULT_GRANT_TYPES = [GrantType::AuthorizationCode->value, GrantType::RefreshToken->value];

    public const array DEFAULT_ALLOWED_SCOPES = ['openid', 'profile', 'email'];

    protected string $extensionAlias = 'heidi';

    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
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
            ->end()
            ->end()
            ->arrayNode('keys')
            ->info('Where the signing keys live: sealed by the KMS named here, stored as files until a table takes over (architecture §3.3).')
            ->isRequired()
            ->children()
            ->scalarNode('kms')
            ->info('DSN of the KMS that seals the private keys ("sodium://..." locally, a Vault or cloud scheme in production); the KMS keeps, it never signs.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('key_id')
            ->info('The key of that KMS the signing keys are sealed under (backend-specific: the id of a sodium key, a Vault transit key name, an ARN).')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('storage')
            ->info('Directory of the sealed signing keys, one file per key and per tenant.')
            ->defaultValue('%kernel.project_dir%/var/keys')
            ->cannotBeEmpty()
            ->end()
            ->end()
            ->end()
            ->arrayNode('tokens')
            ->info('Lifetimes in seconds. The defaults are the choices of architecture §9.')
            ->addDefaultsIfNotSet()
            ->children()
            ->integerNode('authorization_code_ttl')
            ->info('RFC 6749 §4.1.2 recommends ten minutes at most; sixty seconds bound the injection window.')
            ->defaultValue(60)
            ->min(1)
            ->max(self::MAX_AUTHORIZATION_CODE_TTL)
            ->end()
            ->integerNode('access_token_ttl')
            ->info('Access tokens are stateless and cannot be revoked: a short lifetime bounds the exposure.')
            ->defaultValue(600)
            ->min(1)
            ->end()
            ->integerNode('id_token_ttl')
            ->defaultValue(600)
            ->min(1)
            ->end()
            ->integerNode('refresh_token_ttl')
            ->info('Sliding lifetime of a refresh token, renewed at each rotation.')
            ->defaultValue(2592000)
            ->min(1)
            ->end()
            ->integerNode('refresh_token_absolute_ttl')
            ->info('Lifetime of a refresh token family from the authorization that started it; no rotation extends it.')
            ->defaultValue(7776000)
            ->min(1)
            ->end()
            ->end()
            ->validate()
            ->ifTrue(static fn (array $tokens): bool => is_int($tokens['refresh_token_ttl']) && is_int($tokens['refresh_token_absolute_ttl']) && $tokens['refresh_token_ttl'] > $tokens['refresh_token_absolute_ttl'])
            ->thenInvalid('The sliding lifetime of a refresh token (refresh_token_ttl) cannot exceed the absolute lifetime of its family (refresh_token_absolute_ttl).')
            ->end()
            ->end()
            ->arrayNode('clients')
            ->info('The clients of the tenant, keyed by client identifier. A secret is hashed when the client is loaded and never kept in clear.')
            ->useAttributeAsKey('client_id')
            ->normalizeKeys(false)
            ->arrayPrototype()
            ->children()
            ->scalarNode('name')
            ->info('Shown on the consent page; the client identifier when absent.')
            ->defaultNull()
            ->end()
            ->scalarNode('secret')
            ->info('At least 32 visible ASCII characters, generated, never chosen; absent for a public client.')
            ->defaultNull()
            ->end()
            ->arrayNode('redirect_uris')
            ->info('Compared byte for byte with the redirect_uri of a request (RFC 6749 §3.1.2.3); HTTPS, or plain HTTP on a loopback host.')
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('post_logout_redirect_uris')
            ->info('Compared byte for byte with the post_logout_redirect_uri of a logout request (RP-Initiated Logout §3).')
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('grant_types')
            ->defaultValue(self::DEFAULT_GRANT_TYPES)
            ->enumPrototype()
            ->values(array_column(GrantType::cases(), 'value'))->end()
            ->end()
            ->arrayNode('allowed_scopes')
            ->defaultValue(self::DEFAULT_ALLOWED_SCOPES)
            ->scalarPrototype()
            ->end()
            ->end()
            ->enumNode('token_endpoint_auth_method')
            ->values(array_column(TokenEndpointAuthMethod::cases(), 'value'))
            ->defaultValue(TokenEndpointAuthMethod::ClientSecretBasic->value)
            ->end()
            ->booleanNode('requires_consent')
            ->info('Consent is the rule; a first-party application is the named exception.')
            ->defaultTrue()
            ->end()
            ->enumNode('id_token_signed_response_alg')
            ->values(array_column(SignatureAlgorithm::cases(), 'value'))
            ->defaultValue(SignatureAlgorithm::RS256->value)
            ->end()
            ->end()
            ->end()
            ->end()
            ->end();
    }

    /**
     * @param array<array-key, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../config/services.php');

        // A process serves both planes unless its environment says otherwise (architecture §5.2, §6).
        if (! $builder->hasParameter('env(HEIDI_PLANE)')) {
            $builder->setParameter('env(HEIDI_PLANE)', Plane::All->value);
        }

        $tenant = self::section($config, 'tenant');
        $keys = self::section($config, 'keys');
        $tokens = self::section($config, 'tokens');

        $services = $container->services();
        $services->get(TenantFactory::class)
            ->arg('$issuer', self::string($tenant, 'issuer'))
            ->arg('$slug', self::string($tenant, 'slug'))
            ->arg('$name', is_string($tenant['name'] ?? null) ? $tenant['name'] : null);

        // Built from the DSN by the factory registry of symfony/key-management, so that every backend the
        // application installed (local, Vault, cloud) answers to its scheme; the DSN is an argument, not a
        // parameter, because it may carry key material.
        $services->set('heidi.kms', EncrypterInterface::class)
            ->factory([service('key_management.factory'), 'fromString'])
            ->args([self::string($keys, 'kms')]);
        $services->set('heidi.kms.envelopes', EnvelopeEncrypter::class)
            ->args([service('heidi.kms')]);
        $services->get(EnvelopeKeySealer::class)
            ->arg('$envelopes', service('heidi.kms.envelopes'))
            ->arg('$kmsKeyId', self::string($keys, 'key_id'));
        $services->get(FileSigningKeyRepository::class)
            ->arg('$directory', self::string($keys, 'storage'));

        $services->get(AuthorizationHandler::class)
            ->arg('$codeLifetime', self::seconds($tokens, 'authorization_code_ttl'));
        $services->get(JwtAccessTokenIssuer::class)
            ->arg('$lifetime', self::seconds($tokens, 'access_token_ttl'));
        $services->get(JwtIdTokenIssuer::class)
            ->arg('$lifetime', self::seconds($tokens, 'id_token_ttl'));
        $services->get(TokenIssuer::class)
            ->arg('$refreshTokenLifetime', self::seconds($tokens, 'refresh_token_ttl'));
        $services->get(AuthorizationCodeGrant::class)
            ->arg('$refreshTokenFamilyLifetime', self::seconds($tokens, 'refresh_token_absolute_ttl'));

        $services->get(ConfigurationClientRepository::class)
            ->arg('$definitions', is_array($config['clients'] ?? null) ? $config['clients'] : []);
    }

    /**
     * @param array<array-key, mixed> $config
     *
     * @return array<array-key, mixed>
     */
    private static function section(array $config, string $key): array
    {
        $section = $config[$key] ?? null;

        return is_array($section) ? $section : [];
    }

    /**
     * @param array<array-key, mixed> $section
     */
    private static function string(array $section, string $key): string
    {
        $value = $section[$key] ?? null;
        if (! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "heidi" configuration key "%s" must be a string.', $key));
        }

        return $value;
    }

    /**
     * A DateInterval built by the container, from a number of seconds or from the environment placeholder
     * that stands for it until runtime.
     *
     * @param array<array-key, mixed> $section
     */
    private static function seconds(array $section, string $key): object
    {
        $value = $section[$key] ?? null;
        if (! is_int($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "heidi" configuration key "%s" must be a number of seconds.', $key));
        }

        return inline_service(DateInterval::class)
            ->args(['PT' . $value . 'S']);
    }
}
