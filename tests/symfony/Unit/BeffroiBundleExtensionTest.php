<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit;

use DateInterval;
use Beffroi\Bundle\BeffroiBundle;
use Beffroi\Bundle\Key\DormantKeyAlgorithms;
use Beffroi\Bundle\Key\FileTenantKeyRepository;
use Beffroi\Bundle\Key\StagingDelay;
use Beffroi\Bundle\Saml\JoseSamlSigningAlgorithms;
use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Tenant\TenantFactory;
use Beffroi\Core\Application\Key\KeyStaging;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\Vapid;
use Beffroi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Beffroi\Oidc\Application\Authorization\AuthorizationCodeIssuer;
use Beffroi\Oidc\Application\Client\Registration\OpenRegistrationAuthorization;
use Beffroi\Oidc\Application\Token\AuthorizationCodeGrant;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Application\Token\JwtAccessTokenVerifier;
use Beffroi\Oidc\Application\Token\JwtIdTokenIssuer;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenVerifier;
use Beffroi\Oidc\Application\Token\TokenIssuer;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRegistrationPolicy;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use Beffroi\Saml\Application\Metadata\IdentityProviderMetadataHandler;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

/**
 * What the extension hands the services from the configuration, read on the definitions before the
 * container is compiled: the values of "beffroi.tokens" become the DateIntervals of the use cases, the
 * values of "beffroi.keys" and "beffroi.tenant" the arguments of the bridges.
 */
final class BeffroiBundleExtensionTest extends TestCase
{
    #[Test]
    public function theLifetimesOfTheConfigurationReachTheUseCases(): void
    {
        // When
        $container = self::load([
            'tokens' => [
                'authorization_code_ttl' => 45,
                'access_token_ttl' => 300,
                'id_token_ttl' => 120,
                'refresh_token_ttl' => 1000,
                'refresh_token_absolute_ttl' => 2000,
            ],
        ]);

        // Then
        static::assertSame('PT45S', self::interval($container, AuthorizationCodeIssuer::class, '$lifetime'));
        static::assertSame('PT300S', self::interval($container, JwtAccessTokenIssuer::class, '$lifetime'));
        static::assertSame('PT300S', self::interval($container, OpaqueAccessTokenIssuer::class, '$lifetime'));
        static::assertSame('PT120S', self::interval($container, JwtIdTokenIssuer::class, '$lifetime'));
        static::assertSame('PT1000S', self::interval($container, TokenIssuer::class, '$refreshTokenLifetime'));
        static::assertSame('PT2000S', self::interval($container, AuthorizationCodeGrant::class, '$refreshTokenFamilyLifetime'));
    }

    #[Test]
    public function theTenantAndTheKeysReachTheBridges(): void
    {
        // When
        $container = self::load([
            'tenant' => [
                'issuer' => 'https://op.test/tenant-a',
                'slug' => 'tenant-a',
                'name' => 'Tenant A',
            ],
            'keys' => [
                'kms' => 'op',
                'key_id' => 'k',
                'storage' => '/var/lib/beffroi/keys',
            ],
        ]);

        // Then
        $factory = $container->getDefinition(TenantFactory::class);
        static::assertSame('https://op.test/tenant-a', $factory->getArgument('$issuer'));
        static::assertSame('tenant-a', $factory->getArgument('$slug'));
        static::assertSame('Tenant A', $factory->getArgument('$name'));
        static::assertSame('key_management.op', (string) $container->getAlias('beffroi.kms'));
        static::assertSame('k', $container->getDefinition(EnvelopeKeySealer::class)->getArgument('$kmsKeyId'));
        static::assertSame('/var/lib/beffroi/keys', $container->getDefinition(FileTenantKeyRepository::class)->getArgument('$directory'));
    }

    /**
     * Architecture §3.3: the staging delay derives from the JWK Set max-age unless the configuration sets
     * it; the derivation happens at runtime, so that an environment placeholder can stand for either.
     */
    #[Test]
    public function theStagingDelayDerivesFromTheJwksMaxAgeUnlessSet(): void
    {
        // When
        $container = self::load([
            'keys' => [
                'kms' => 'op',
                'key_id' => 'k',
                'jwks_max_age' => 120,
            ],
        ]);

        // Then
        $delay = $container->getDefinition(KeyStaging::class)->getArgument('$stagingDelay');
        static::assertInstanceOf(Definition::class, $delay);
        $factory = $delay->getFactory();
        static::assertIsArray($factory);
        static::assertSame(StagingDelay::class, $factory[0]);
        static::assertSame('interval', $factory[1]);
        static::assertSame([null, 120], $delay->getArguments());
    }

    #[Test]
    public function aConfiguredStagingDelayReachesTheStaging(): void
    {
        // When
        $container = self::load([
            'keys' => [
                'kms' => 'op',
                'key_id' => 'k',
                'jwks_max_age' => 120,
                'staging_delay' => 30,
            ],
        ]);

        // Then
        $delay = $container->getDefinition(KeyStaging::class)->getArgument('$stagingDelay');
        static::assertInstanceOf(Definition::class, $delay);
        static::assertSame([30, 120], $delay->getArguments());
    }

    /**
     * Decision 0009: what a tenant does with a client that registers itself reaches the bridge that
     * answers for that tenant, the mode it names and the two durations it keeps a client for.
     */
    #[Test]
    public function theRegistrationPolicyOfTheConfigurationReachesTheBridge(): void
    {
        // When
        $container = self::load([
            'client_registration' => [
                'mode' => OpenRegistrationAuthorization::MODE,
                'exempt_confidential_clients_from_pkce' => true,
                'keep_a_client_unused_for' => 86400,
                'keep_a_client_never_used_for' => 3600,
            ],
        ]);

        // Then
        $policies = $container->getDefinition(ConfigurationClientRegistrationPolicy::class);
        static::assertSame(OpenRegistrationAuthorization::MODE, $policies->getArgument('$mode'));
        static::assertTrue($policies->getArgument('$exemptsConfidentialClientsFromPkce'));
        static::assertSame('PT86400S', self::interval($container, ConfigurationClientRegistrationPolicy::class, '$keepsAClientUnusedFor'));
        static::assertSame('PT3600S', self::interval($container, ConfigurationClientRegistrationPolicy::class, '$keepsAClientNeverUsedFor'));
    }

    /**
     * Decision 0009: closed is the default, and the mode is a value of one tenant's policy: there is no
     * key here, whatever its name, that opens a registration endpoint for a deployment. What a deployment
     * that writes nothing hands the bridge is no mode at all, which is no policy and no endpoint.
     */
    #[Test]
    public function aDeploymentThatWritesNothingHandsTheBridgeNoMode(): void
    {
        // When
        $container = self::load([]);

        // Then
        static::assertNull($container->getDefinition(ConfigurationClientRegistrationPolicy::class)->getArgument('$mode'));
    }

    #[Test]
    public function theClientsReachTheConfigurationRepository(): void
    {
        // When
        $container = self::load([
            'clients' => [
                'app' => [
                    'redirect_uris' => ['https://app.test/cb'],
                    'token_endpoint_auth_method' => 'none',
                ],
            ],
        ]);

        // Then
        $clients = $container->getDefinition(ConfigurationClientRepository::class)->getArgument('$definitions');
        static::assertIsArray($clients);
        static::assertSame(['app'], array_keys($clients));
    }

    /**
     * Architecture §4.6: the shape is a per-client option. The tree reads the name and nothing else; a
     * client that names none leaves it to the wiring, which is what knows the shapes and their order.
     */
    #[Test]
    public function theAccessTokenShapeOfAClientIsRead(): void
    {
        // When
        $container = self::load([
            'clients' => [
                'app' => [
                    'redirect_uris' => ['https://app.test/cb'],
                    'token_endpoint_auth_method' => 'none',
                ],
                'api-app' => [
                    'redirect_uris' => ['https://api.test/cb'],
                    'token_endpoint_auth_method' => 'none',
                    'access_token_format' => 'opaque',
                ],
            ],
        ]);

        // Then
        $clients = $container->getDefinition(ConfigurationClientRepository::class)->getArgument('$definitions');
        static::assertIsArray($clients);
        static::assertIsArray($clients['app']);
        static::assertIsArray($clients['api-app']);
        static::assertNull($clients['app']['access_token_format']);
        static::assertSame('opaque', $clients['api-app']['access_token_format']);
    }

    /**
     * Architecture §4.6: one class per shape, tagged, and the shape it writes is the issuer's own
     * business; the wiring holds an order and no name (issue #239).
     */
    #[Test]
    public function theAccessTokenIssuersAreTaggedAndNothingNamesTheirShape(): void
    {
        // When
        $container = self::load([]);

        // Then
        foreach ([JwtAccessTokenIssuer::class, OpaqueAccessTokenIssuer::class] as $issuer) {
            static::assertArrayHasKey('beffroi.oidc.access_token_issuer', $container->getDefinition($issuer)->getTags());
        }
        foreach ([JwtAccessTokenVerifier::class, OpaqueAccessTokenVerifier::class] as $verifier) {
            static::assertArrayHasKey('beffroi.oidc.access_token_verifier', $container->getDefinition($verifier)->getTags());
        }
    }

    /**
     * Architecture §5.2: a process serves both planes unless BEFFROI_PLANE says otherwise.
     */
    #[Test]
    public function theDefaultPlaneIsBoth(): void
    {
        // When
        $container = self::load([]);

        // Then
        static::assertSame('all', $container->getParameterBag()->all()['env(BEFFROI_PLANE)']);
    }

    /**
     * The application may set the default plane of its processes itself; the bundle does not override it.
     */
    #[Test]
    public function theApplicationKeepsItsOwnDefaultPlane(): void
    {
        // Given
        $container = new ContainerBuilder();
        $container->setParameter('env(BEFFROI_PLANE)', 'protocol');

        // When
        self::load([], $container);

        // Then
        static::assertSame('protocol', $container->getParameterBag()->all()['env(BEFFROI_PLANE)']);
    }

    /**
     * Decisions 0011 and 0018: what registers the encrypted types runs while the bundles boot, and what it
     * is handed is the encrypter of the sealed columns, so an encrypter built there would build the store,
     * the connection and the KMS client of every process that boots. It is lazy, and public because a
     * private service with one consumer is inlined and an inlined service is not a proxy.
     */
    #[Test]
    public function theEncrypterOfTheSealedColumnsIsLazySoThatABootReachesNoKms(): void
    {
        // When
        $container = self::load([]);

        // Then
        $encrypter = $container->getDefinition('beffroi.personal_data.encrypter');
        static::assertTrue($encrypter->isLazy());
        static::assertTrue($encrypter->isPublic());
    }

    /**
     * beffroi/saml, spec/saml.md section 5.1: a deployment that does not enable the SAML identity provider draws no
     * SAML key, its algorithm being wired by nothing.
     */
    #[Test]
    public function aDeploymentWithoutTheSamlIdentityProviderDrawsNoSamlKey(): void
    {
        // When
        $container = self::load([]);

        // Then
        static::assertFalse($container->getDefinition(SamlSigning::class)->hasTag(JoseSamlSigningAlgorithms::TAG));
    }

    /**
     * Spec/saml.md section 5.1, S-1, S-2: enabled, the algorithm of the SAML key is wired with the others, so that
     * the key commands and the scheduled step treat it as every key of the tenant.
     */
    #[Test]
    public function enablingTheSamlIdentityProviderWiresItsKey(): void
    {
        // When
        $container = self::load([
            'saml' => [
                'identity_provider' => null,
            ],
        ]);

        // Then
        static::assertTrue($container->getDefinition(SamlSigning::class)->hasTag(JoseSamlSigningAlgorithms::TAG));
    }

    /**
     * Spec/saml.md section 5.1: the algorithm of a capability a deployment leaves off is dormant, so that a key the
     * tenant drew while it was on is read by nothing rather than refused as a fault of the storage.
     *
     * @param class-string $algorithm
     */
    #[Test]
    #[DataProvider('provideCapabilitiesLeftOff')]
    public function theAlgorithmOfACapabilityLeftOffIsDormant(string $algorithm): void
    {
        // When
        $container = self::load([]);

        // Then
        static::assertTrue($container->getDefinition($algorithm)->hasTag(DormantKeyAlgorithms::TAG));
    }

    /**
     * @return iterable<string, array{class-string}>
     */
    public static function provideCapabilitiesLeftOff(): iterable
    {
        yield 'the SAML identity provider' => [SamlSigning::class];
        yield 'web push' => [Vapid::class];
    }

    /**
     * Spec/saml.md section 5.1: turned on, the algorithm of the capability is not dormant, so that the key the tenant
     * drew is in service as it was.
     *
     * @param array<string, mixed> $config
     * @param class-string $algorithm
     */
    #[Test]
    #[DataProvider('provideCapabilitiesTurnedOn')]
    public function theAlgorithmOfACapabilityTurnedOnIsNotDormant(array $config, string $algorithm): void
    {
        // When
        $container = self::load($config);

        // Then
        static::assertFalse($container->getDefinition($algorithm)->hasTag(DormantKeyAlgorithms::TAG));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, class-string}>
     */
    public static function provideCapabilitiesTurnedOn(): iterable
    {
        yield 'the SAML identity provider' => [
            [
                'saml' => [
                    'identity_provider' => null,
                ],
            ],
            SamlSigning::class,
        ];
        yield 'web push' => [
            [
                'web_push' => [
                    'subject' => 'mailto:operator@op.test',
                ],
            ],
            Vapid::class,
        ];
    }

    /**
     * Spec/saml.md S-4, section 6.1 steps 4 and 6: WantAuthnRequestsSigned true unless the tenant says otherwise, and
     * the metadata cacheable for the max-age of its keys.
     *
     * @param array<string, mixed> $identityProvider
     */
    #[Test]
    #[DataProvider('provideIdentityProviders')]
    public function theSettingsOfTheIdentityProviderReachItsMetadata(array $identityProvider, bool $wantAuthnRequestsSigned): void
    {
        // When
        $container = self::load([
            'keys' => [
                'kms' => 'op',
                'key_id' => 'signing',
                'jwks_max_age' => 90,
            ],
            'saml' => [
                'identity_provider' => $identityProvider,
            ],
        ]);

        // Then
        $handler = $container->getDefinition(IdentityProviderMetadataHandler::class);
        static::assertSame(
            [$wantAuthnRequestsSigned, 90],
            [$handler->getArgument('$wantAuthnRequestsSigned'), $handler->getArgument('$maxAge')],
        );
    }

    /**
     * @return iterable<string, array{array<string, mixed>, bool}>
     */
    public static function provideIdentityProviders(): iterable
    {
        yield 'the default' => [[], true];
        yield 'signed requests turned off' => [
            [
                'want_authn_requests_signed' => false,
            ],
            false,
        ];
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function load(array $config, ?ContainerBuilder $container = null): ContainerBuilder
    {
        $container ??= new ContainerBuilder();
        $extension = new BeffroiBundle()->getContainerExtension();
        static::assertNotNull($extension);
        $extension->load([
            $config
                + [
                    'tenant' => [
                        'issuer' => 'https://op.test',
                    ],
                    'keys' => [
                        'kms' => 'op',
                        'key_id' => 'signing',
                    ],
                ],
        ], $container);

        return $container;
    }

    private static function interval(ContainerBuilder $container, string $service, string $argument): string
    {
        $definition = $container->getDefinition($service)->getArgument($argument);
        static::assertInstanceOf(Definition::class, $definition);
        static::assertSame(DateInterval::class, $definition->getClass());
        $spec = $definition->getArgument(0);
        static::assertIsString($spec);

        return $spec;
    }
}
