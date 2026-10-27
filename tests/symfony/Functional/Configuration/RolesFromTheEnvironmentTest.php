<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Configuration;

use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Core\Port\ApplicationServerAlgorithmsInterface;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\SamlLoader;
use function array_map;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0030, issue #915: whether the tenant is a SAML identity provider, a SAML service provider, and whether it
 * reaches its users by push, a deployment names by environment, a role being read when the container builds what it
 * changes. The kernel of these tests switches each role by a variable (config_test_environment_roles.yml), so each test
 * names the values before it boots one, as a deployment names them before it starts, and a role turned off is
 * answered as one that was never declared (spec/saml.md S-40, S-41, architecture §5.6).
 */
final class RolesFromTheEnvironmentTest extends ConsoleTestCase
{
    private const string ENVIRONMENT = 'test_environment_roles';

    private const array VARIABLES = [
        'BEFFROI_TEST_SAML_IDENTITY_PROVIDER',
        'BEFFROI_TEST_SAML_SERVICE_PROVIDER',
        'BEFFROI_TEST_SAML_SERVICE_PROVIDER_ENTITY_ID',
        'BEFFROI_TEST_WEB_PUSH_SUBJECT',
    ];

    protected function tearDown(): void
    {
        parent::tearDown();
        foreach (self::VARIABLES as $name) {
            unset($_SERVER[$name], $_ENV[$name]);
        }
    }

    protected static function kernelOptions(): array
    {
        return [
            'environment' => self::ENVIRONMENT,
        ];
    }

    /**
     * Spec/saml.md section 6.1: the identity provider the environment leaves on serves its metadata.
     */
    #[Test]
    public function anIdentityProviderTheEnvironmentLeavesOnServesItsMetadata(): void
    {
        // Given
        self::drawTheSamlKey();

        // When
        $this->browser->request('GET', '/saml/metadata');

        // Then
        static::assertSame('https://op.test/saml/metadata', $this->servedDescriptor()->entityId);
    }

    /**
     * S-41: the identity provider the environment turns off serves no metadata, though the tenant holds a SAML key in
     * service for the service provider.
     */
    #[Test]
    public function anIdentityProviderTheEnvironmentTurnsOffServesNoMetadata(): void
    {
        // Given
        $this->deploy([
            'BEFFROI_TEST_SAML_IDENTITY_PROVIDER' => 'false',
            'BEFFROI_TEST_SAML_SERVICE_PROVIDER' => 'true',
        ]);
        self::drawTheSamlKey();

        // When
        $this->browser->request('GET', '/saml/metadata');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Spec/saml.md section 6.9: the service provider the environment turns on serves its metadata, named by the URL of
     * its metadata while the environment names no entity ID.
     */
    #[Test]
    public function aServiceProviderTheEnvironmentTurnsOnServesItsMetadata(): void
    {
        // Given
        $this->deploy([
            'BEFFROI_TEST_SAML_SERVICE_PROVIDER' => 'true',
        ]);
        self::drawTheSamlKey();

        // When
        $this->browser->request('GET', '/saml/sp/metadata');

        // Then
        static::assertSame('https://op.test/saml/sp/metadata', $this->servedDescriptor()->entityId);
    }

    /**
     * S-38: the service provider goes by the entity ID the environment names.
     */
    #[Test]
    public function aServiceProviderGoesByTheEntityIdTheEnvironmentNames(): void
    {
        // Given
        $this->deploy([
            'BEFFROI_TEST_SAML_SERVICE_PROVIDER' => 'true',
            'BEFFROI_TEST_SAML_SERVICE_PROVIDER_ENTITY_ID' => 'urn:example:op:service-provider',
        ]);
        self::drawTheSamlKey();

        // When
        $this->browser->request('GET', '/saml/sp/metadata');

        // Then
        static::assertSame('urn:example:op:service-provider', $this->servedDescriptor()->entityId);
    }

    /**
     * S-41: the service provider the environment leaves off serves no metadata, though the tenant holds a SAML key in
     * service for the identity provider.
     */
    #[Test]
    public function aServiceProviderTheEnvironmentLeavesOffServesNoMetadata(): void
    {
        // Given
        self::drawTheSamlKey();

        // When
        $this->browser->request('GET', '/saml/sp/metadata');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * S-40: with both roles turned off by the environment, the tenant draws no SAML key, its algorithm out of the
     * registry of its family.
     */
    #[Test]
    public function aTenantWhoseRolesTheEnvironmentTurnsOffDrawsNoSamlKey(): void
    {
        // Given
        $this->deploy([
            'BEFFROI_TEST_SAML_IDENTITY_PROVIDER' => 'false',
        ]);

        // When
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('This provider signs no SAML message with a key named "SAML-SIGNING"; it serves no SAML.', self::flattened($tester));
    }

    /**
     * Spec/saml.md section 5.1: the SAML key the tenant drew while the identity provider was on stays where it is once
     * the environment turns both roles off, dormant: the keys of the tenant go on without it.
     */
    #[Test]
    public function aSamlKeyDrawnBeforeTheEnvironmentTurnedTheRolesOffIsDormant(): void
    {
        // Given
        self::drawTheSamlKey();
        $this->deploy([
            'BEFFROI_TEST_SAML_IDENTITY_PROVIDER' => 'false',
        ]);

        // When
        $inService = self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class)->findInService(self::tenant());

        // Then
        static::assertSame([], $inService);
    }

    /**
     * Architecture §5.6, RFC 8292 §2: web push is on while the environment names a subject, the tenant handing out
     * the key of its algorithm.
     */
    #[Test]
    public function webPushIsOnWhileTheEnvironmentNamesASubject(): void
    {
        // When
        $algorithms = self::applicationServerAlgorithms();

        // Then
        static::assertSame(['VAPID'], $algorithms);
    }

    /**
     * Architecture §5.6: an empty subject is none, and web push is off: the tenant hands out no key, and nothing
     * reaches anybody by push.
     */
    #[Test]
    public function webPushIsOffWhileTheEnvironmentNamesNoSubject(): void
    {
        // Given
        $this->deploy([
            'BEFFROI_TEST_WEB_PUSH_SUBJECT' => '',
        ]);

        // When
        $algorithms = self::applicationServerAlgorithms();

        // Then
        static::assertSame([], $algorithms);
    }

    /**
     * The deployment named before it starts: the variables, then a kernel booted on them.
     *
     * @param array<string, string> $variables
     */
    private function deploy(array $variables): void
    {
        foreach ($variables as $name => $value) {
            $_SERVER[$name] = $value;
        }
        $this->browser = self::browser(null, self::kernelOptions());
        $this->browser->disableReboot();
    }

    /**
     * The SAML key of the tenant, drawn by the command an operator runs and active at once.
     */
    private static function drawTheSamlKey(): void
    {
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
    }

    /**
     * @return list<string>
     */
    private static function applicationServerAlgorithms(): array
    {
        return array_map(
            static fn (KeyAlgorithmInterface $algorithm): string => $algorithm->name(),
            self::service('test.beffroi.environment_roles.application_server_algorithms', ApplicationServerAlgorithmsInterface::class)->all(),
        );
    }

    private function servedDescriptor(): EntityDescriptor
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());

        return new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(SamlLoader::create()->load(self::string($response->getContent())));
    }
}
