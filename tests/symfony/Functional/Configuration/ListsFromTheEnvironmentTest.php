<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Configuration;

use App\Doctrine\PersonalData\TenantDataKeyStores;
use App\Locale\ServedLocales;
use App\Tenant\TenantFactory;
use Beffroi\Core\Bridge\Configuration\ConfigurationAdministratorGroups;
use Beffroi\Core\Domain\Tenant\Tenant;
use function array_map;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRegistrationPolicy;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationDeclaredScopes;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationTrustedIssuers;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Decision 0030
 */
final class ListsFromTheEnvironmentTest extends KernelTestCase
{
    private const string ENVIRONMENT = 'test_environment_lists';

    private const array VARIABLES = [
        'BEFFROI_TEST_TRUSTED_ISSUERS',
        'BEFFROI_TEST_STATEMENT_ISSUERS',
        'BEFFROI_TEST_SELF_SERVED_CLAIMS',
        'BEFFROI_TEST_AUTHENTICATION_CLASSES',
        'BEFFROI_TEST_DATA_KEY_SECRETS',
        'BEFFROI_TEST_SAML_SERVICE_PROVIDERS',
        'BEFFROI_TEST_SAML_IDENTITY_PROVIDERS',
        'BEFFROI_TEST_TENANT_SCOPES',
        'BEFFROI_TEST_TENANT_ADMINISTRATORS',
        'BEFFROI_TEST_LOCALES',
    ];

    private const array JWKS = [
        'keys' => [
            [
                'kid' => 'unused-by-any-test',
                'use' => 'sig',
                'alg' => 'ES256',
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'nvfyLGCh4Bxayqp4rpQigJRhCIaofoBZKddnkjIihiU',
                'y' => 'ZcMX1QlOsgcws1aY6yTFPdU9wCp6ZwgtKQEajS5iWZk',
            ],
        ],
    ];

    protected function tearDown(): void
    {
        parent::tearDown();
        foreach (self::VARIABLES as $name) {
            unset($_SERVER[$name], $_ENV[$name]);
        }
    }

    /**
     * RFC 7523 §2.1
     */
    #[Test]
    public function aTrustedIssuerTheEnvironmentDeclaresIsTrusted(): void
    {
        // Given
        self::carry('BEFFROI_TEST_TRUSTED_ISSUERS', [
            'https://issuer.example' => [
                'jwks_uri' => 'https://issuer.example/jwks',
                'signing_algorithms' => ['ES256'],
                'clients' => ['assertion-app'],
                'identity_provider' => 'workforce',
                'trusted_scopes' => ['invoices.read'],
            ],
        ]);

        // When
        $issuer = self::service('test.beffroi.environment_lists.trusted_issuers', ConfigurationTrustedIssuers::class)
            ->find(self::tenant(), 'https://issuer.example');

        // Then
        static::assertSame(['assertion-app'], $issuer?->clientIds);
    }

    /**
     * Decision 0030
     */
    #[Test]
    public function aListTheTreeRefusesIsRefusedWhenItsServiceIsBuilt(): void
    {
        // Given
        self::carry('BEFFROI_TEST_TRUSTED_ISSUERS', [
            'https://issuer.example' => [
                'jwks_uri' => 'https://issuer.example/jwks',
                'signing_algorithms' => ['ES256'],
                'clients' => ['assertion-app'],
                'insecure' => true,
            ],
        ]);
        self::bootKernel(['environment' => self::ENVIRONMENT]);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIsOrContains('The "beffroi" configuration key "trusted_issuers" carried by the environment is refused: Unrecognized option "insecure" under "trusted_issuers.https://issuer.example".');

        // When
        static::getContainer()->get('test.beffroi.environment_lists.trusted_issuers');
    }

    /**
     * RFC 7591 §2.3
     */
    #[Test]
    public function anAuthorityTheEnvironmentPinsIsTrustedForItsStatements(): void
    {
        // Given
        self::carry('BEFFROI_TEST_STATEMENT_ISSUERS', [
            'https://store.example' => [
                'jwks' => self::JWKS,
                'signing_algorithms' => ['ES256'],
            ],
        ]);

        // When
        $policy = self::service('test.beffroi.environment_lists.registration_policy', ConfigurationClientRegistrationPolicy::class)->policyFor(self::tenant());

        // Then
        static::assertNotNull($policy?->trusts('https://store.example'));
    }

    #[Test]
    public function theClaimsAPersonChangesAreTheOnesTheEnvironmentOpens(): void
    {
        // Given
        self::carry('BEFFROI_TEST_SELF_SERVED_CLAIMS', ['nickname', 'locale']);

        // When
        $claims = self::service('test.beffroi.environment_lists.tenant_factory', TenantFactory::class)->selfServedClaims();

        // Then
        static::assertSame(['nickname', 'locale'], $claims->toDocument());
    }

    /**
     * Decision 0010
     */
    #[Test]
    public function theVocabularyOfTheTenantIsTheOneTheEnvironmentNames(): void
    {
        // Given
        self::carry('BEFFROI_TEST_AUTHENTICATION_CLASSES', ['gold' => 'phishing_resistant', 'silver' => 'single_factor']);

        // When
        $policy = self::service('test.beffroi.environment_lists.tenant_factory', TenantFactory::class)->authenticationContextPolicy();

        // Then
        static::assertSame(['gold', 'silver'], $policy->names());
    }

    #[Test]
    public function theScopesOfTheTenantAreTheOnesTheEnvironmentDeclares(): void
    {
        // Given
        self::carry('BEFFROI_TEST_TENANT_SCOPES', ['invoices.read', 'invoices.pay']);

        // When
        $scopes = self::service('test.beffroi.environment_lists.declared_scopes', ConfigurationDeclaredScopes::class)->scopesDeclaredFor(self::tenant());

        // Then
        static::assertSame(['invoices.read', 'invoices.pay'], array_map(static fn (Scope $scope): string => $scope->value, $scopes));
    }

    /**
     * Decision 0030
     */
    #[Test]
    public function aScopeTheTreeRefusesIsRefusedWhenItsServiceIsBuilt(): void
    {
        // Given
        self::carry('BEFFROI_TEST_TENANT_SCOPES', [['invoices.read']]);
        self::bootKernel(['environment' => self::ENVIRONMENT]);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIsOrContains('The "beffroi" configuration key "tenant.scopes" carried by the environment is refused:');

        // When
        static::getContainer()->get('test.beffroi.environment_lists.declared_scopes');
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function theGroupsThatAdministerTheTenantAreTheOnesTheEnvironmentNames(): void
    {
        // Given
        self::carry('BEFFROI_TEST_TENANT_ADMINISTRATORS', ['administrators', 'operators']);

        // When
        $groups = self::service('test.beffroi.environment_lists.administrator_groups', ConfigurationAdministratorGroups::class)
            ->groupsAdministering(self::tenant());

        // Then
        static::assertSame(['administrators', 'operators'], $groups);
    }

    /**
     * Decision 0030
     */
    #[Test]
    public function aGroupTheTreeRefusesIsRefusedWhenItsServiceIsBuilt(): void
    {
        // Given
        self::carry('BEFFROI_TEST_TENANT_ADMINISTRATORS', [['administrators']]);
        self::bootKernel(['environment' => self::ENVIRONMENT]);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIsOrContains('The "beffroi" configuration key "tenant.administrators" carried by the environment is refused:');

        // When
        static::getContainer()->get('test.beffroi.environment_lists.administrator_groups');
    }

    /**
     * Decision 0018
     */
    #[Test]
    public function theSecretsThatBindTheDataKeysMayComeFromTheEnvironment(): void
    {
        // Given
        self::carry('BEFFROI_TEST_DATA_KEY_SECRETS', ['a-new-secret-of-these-tests', 'an-old-secret-of-these-tests']);
        self::bootKernel(['environment' => self::ENVIRONMENT]);

        // When
        $stores = static::getContainer()->get('test.beffroi.environment_lists.data_keys');

        // Then
        static::assertInstanceOf(TenantDataKeyStores::class, $stores);
    }

    /**
     * Decision 0018
     */
    #[Test]
    public function noSecretToBindTheDataKeysIsRefused(): void
    {
        // Given
        self::carry('BEFFROI_TEST_DATA_KEY_SECRETS', []);
        self::bootKernel(['environment' => self::ENVIRONMENT]);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIsOrContains('The "beffroi" configuration key "keys.data_key_secrets" carried by the environment is refused:');

        // When
        static::getContainer()->get('test.beffroi.environment_lists.data_keys');
    }

    /**
     * Spec/saml.md S-5
     */
    #[Test]
    public function aServiceProviderTheEnvironmentDeclaresIsServed(): void
    {
        // Given
        self::carry('BEFFROI_TEST_SAML_SERVICE_PROVIDERS', [
            'https://sp.example.org/saml' => [
                'metadata' => '/srv/saml/sp-example-org-metadata.xml',
                'attributes' => [
                    'urn:oid:0.9.2342.19200300.100.1.3' => ['claim' => 'email'],
                ],
            ],
        ]);

        // When
        $serviceProvider = self::service('test.beffroi.environment_lists.service_providers', ConfigurationServiceProviders::class)
            ->find(self::tenant(), 'https://sp.example.org/saml');

        // Then
        static::assertSame('https://sp.example.org/saml', $serviceProvider?->entityId);
    }

    /**
     * Spec/saml.md S-42, section 5.7
     */
    #[Test]
    public function anUpstreamIdentityProviderOfATenantThatIsNoServiceProviderIsRefused(): void
    {
        // Given
        self::carry('BEFFROI_TEST_SAML_IDENTITY_PROVIDERS', [
            'https://idp.acme.example/saml' => [
                'metadata' => 'https://idp.acme.example/saml/metadata',
                'domains' => ['acme.example'],
                'email_attribute' => 'mail',
            ],
        ]);
        self::bootKernel(['environment' => self::ENVIRONMENT]);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('Upstream identity providers are declared for a tenant that is a SAML service provider: enable "beffroi.saml.service_provider", or remove "beffroi.saml.identity_providers".');

        // When
        static::getContainer()->get('test.beffroi.environment_lists.identity_providers');
    }

    /**
     * Architecture §5.7
     */
    #[Test]
    public function theLanguagesServedAreTheOnesTheEnvironmentNames(): void
    {
        // Given
        self::carry('BEFFROI_TEST_LOCALES', ['fr', 'en']);

        // When
        $served = self::service('test.beffroi.environment_lists.served_locales', ServedLocales::class);

        // Then
        static::assertSame(['en', 'fr'], $served->all);
    }

    /**
     * Architecture §5.7
     */
    #[Test]
    public function aLanguageWithoutACatalogueIsRefusedWhenItsServiceIsBuilt(): void
    {
        // Given
        self::carry('BEFFROI_TEST_LOCALES', ['en', 'sv']);
        self::bootKernel(['environment' => self::ENVIRONMENT]);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "locales" names "sv", which no catalogue of the application holds; it has "en", "fr".');

        // When
        static::getContainer()->get('test.beffroi.environment_lists.served_locales');
    }

    private static function carry(string $variable, mixed $list): void
    {
        $_SERVER[$variable] = json_encode($list, JSON_THROW_ON_ERROR);
    }

    private static function tenant(): Tenant
    {
        return self::service('test.beffroi.environment_lists.tenant_factory', TenantFactory::class)->create();
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return T
     */
    private static function service(string $id, string $class): object
    {
        if (! self::$booted) {
            self::bootKernel(['environment' => self::ENVIRONMENT]);
        }
        $service = static::getContainer()->get($id);
        static::assertInstanceOf($class, $service);

        return $service;
    }
}
