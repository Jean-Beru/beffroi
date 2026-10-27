<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Configuration;

use Beffroi\Bundle\Doctrine\PersonalData\TenantDataKeyStores;
use Beffroi\Bundle\Tenant\TenantFactory;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRegistrationPolicy;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationTrustedIssuers;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Decision 0030, issue #912: a list of the configuration enters by an environment variable of its own, a JSON
 * document of the shape of the list written in the file, and is held to the rules of the tree that list is held to.
 * The kernel of these tests reads every list from a variable (config_test_environment_lists.yml), so each test names
 * the document before it boots one, as a deployment names it before it starts, and reads the service the list
 * reaches.
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
    ];

    /**
     * The public half of a key no test signs anything with, the one config_test.yml pins its authority by.
     */
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
     * RFC 7523 §2.1: the issuer a deployment trusts by environment is the one the tenant trusts, for the clients and
     * the scopes it names.
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
     * Decision 0030: what the tree refuses of a written list it refuses of one the environment carries, here an option
     * no issuer has, when the service the list reaches is built.
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
     * RFC 7591 §2.3: the authority a deployment pins by environment is the one whose statements the tenant reads.
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

    /**
     * Issue #452: the claims a person may change of themselves are the ones the deployment opens by environment.
     */
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
     * Decision 0010: the "acr" vocabulary of the tenant is the one the deployment names by environment, in its order.
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

    /**
     * Decision 0018: the secrets that bind the data keys may come from the environment as the list a rotation keeps
     * two in, the new one first.
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
     * Decision 0018: a data key is bound by one secret at least, which the tree holds a written list to.
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
     * Spec/saml.md S-5: a service provider a deployment declares by environment is served by the identity provider of
     * the tenant, its options defaulted as those of a written one are.
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
     * Spec/saml.md S-42, section 5.7: a tenant that is no service provider receives no assertion of an upstream
     * identity provider, whether the declaration is written or carried by the environment.
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
     * The JSON document a deployment writes into the variable.
     */
    private static function carry(string $variable, mixed $list): void
    {
        $_SERVER[$variable] = json_encode($list, JSON_THROW_ON_ERROR);
    }

    /**
     * The tenant of this kernel, which the lists are declared for.
     */
    private static function tenant(): Tenant
    {
        return self::service('test.beffroi.environment_lists.tenant_factory', TenantFactory::class)->create();
    }

    /**
     * A service of a kernel booted on the variables the test named, once.
     *
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
