<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Saml;

use App\Command\SamlServiceProviderForgetCommand;
use App\Command\SamlServiceProviderRefreshCommand;
use App\Doctrine\TenantProvider;
use App\Message\RefreshTheSamlMetadata;
use App\MessageHandler\RefreshTheSamlMetadataHandler;
use App\Tests\Symfony\Fixture\RecordedMessages;
use App\Tests\Symfony\Functional\Command\ConsoleTestCase;
use Beffroi\Saml\Application\Metadata\MetadataRefresh;
use Beffroi\Saml\Domain\Metadata\PeerInterface;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Writing\MetadataWriter;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Serializer;
use DateTimeImmutable;
use function dirname;
use function file_put_contents;
use function is_dir;
use function mkdir;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\LogLevel;
use function sprintf;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml, spec/saml.md section 6.2
 */
final class ServiceProvidersTest extends ConsoleTestCase
{
    private const string FAR_VALID_UNTIL = '2099-01-01T00:00:00+00:00';

    protected function setUp(): void
    {
        parent::setUp();
        self::mockTime(new DateTimeImmutable('2026-09-15T10:00:00+00:00'));
    }

    /**
     * S-8
     */
    #[Test]
    public function aSimpleSamlPhpServiceProviderIsRegisteredByCommandFromItsMetadata(): void
    {
        // Given
        self::publish(ServiceProviderDocuments::simpleSamlPhp());

        // When
        $tester = self::console(SamlServiceProviderRefreshCommand::NAME);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(
            sprintf('The service provider "%s" is registered from its metadata.', ServiceProviderDocuments::SIMPLESAMLPHP),
            self::flattened($tester),
        );
        static::assertSame(ServiceProviderDocuments::simpleSamlPhp(), self::accepted()?->document);
    }

    /**
     * S-6
     */
    #[Test]
    public function anExpiredDocumentIsRefusedAndTheAcceptedOneKept(): void
    {
        // Given
        self::publish(ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'));
        self::console(SamlServiceProviderRefreshCommand::NAME);
        self::publish(ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-09-15T09:00:00Z'));

        // When
        $tester = self::console(SamlServiceProviderRefreshCommand::NAME);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('The metadata is past its validUntil (M-7).', self::flattened($tester));
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), self::accepted()?->validUntil);
    }

    /**
     * S-6
     */
    #[Test]
    public function theGenuineDocumentReplacesTheDocumentAnAttackerHadAccepted(): void
    {
        // Given
        self::service('test.beffroi.saml_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedServiceProviderMetadata(
                Uuid::v7(),
                self::tenant(),
                ServiceProviderDocuments::SIGNED,
                self::attackerDocument(),
                new DateTimeImmutable(self::FAR_VALID_UNTIL),
                new DateTimeImmutable('2026-09-15T09:00:00+00:00'),
            ));

        // When
        $tester = self::console(SamlServiceProviderRefreshCommand::NAME, [
            'entity-id' => ServiceProviderDocuments::SIGNED,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(
            sprintf('The metadata of the service provider "%s" are refreshed.', ServiceProviderDocuments::SIGNED),
            self::flattened($tester),
        );
        $accepted = self::accepted(ServiceProviderDocuments::SIGNED) ?? static::fail('Nothing is accepted.');
        static::assertSame(ServiceProviderDocuments::exampleOrg(), $accepted->document);
        static::assertNull($accepted->validUntil);
    }

    /**
     * S-7
     */
    #[Test]
    public function aServiceProviderAskingForEncryptionWithoutAKeyIsRefusedAtRegistration(): void
    {
        // Given
        self::publish(ServiceProviderDocuments::simpleSamlPhpWithoutEncryptionKey());

        // When
        $tester = self::console(SamlServiceProviderRefreshCommand::NAME);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(
            'The service provider asks for encrypted assertions and its metadata hold no key for encryption (spec/saml.md S-7).',
            self::flattened($tester),
        );
        static::assertNull(self::accepted());
    }

    /**
     * S-5
     */
    #[Test]
    public function anEntityIdTheConfigurationDoesNotDeclareIsRefused(): void
    {
        // When
        $tester = self::console(SamlServiceProviderRefreshCommand::NAME, [
            'entity-id' => 'https://sp.example.com/saml',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('The tenant declares no service provider "https://sp.example.com/saml"', self::flattened($tester));
    }

    /**
     * S-6, section 6.2, forgotten
     */
    #[Test]
    public function theForgetCommandRemovesTheAcceptedDocument(): void
    {
        // Given
        self::publish(ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-08T00:00:00Z'));
        self::console(SamlServiceProviderRefreshCommand::NAME);

        // When
        $tester = self::console(SamlServiceProviderForgetCommand::NAME, [
            'entity-id' => ServiceProviderDocuments::SIMPLESAMLPHP,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(
            sprintf('The metadata accepted for the service provider "%s" are forgotten;', ServiceProviderDocuments::SIMPLESAMLPHP),
            self::flattened($tester),
        );
        static::assertNull(self::accepted());
    }

    /**
     * S-6, section 6.2, forgotten
     */
    #[Test]
    public function aForgottenServiceProviderIsRegisteredAgainAtTheNextRefresh(): void
    {
        // Given
        self::publish(ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-08T00:00:00Z'));
        self::console(SamlServiceProviderRefreshCommand::NAME);
        self::publish(ServiceProviderDocuments::simpleSamlPhp());
        self::console(SamlServiceProviderForgetCommand::NAME, [
            'entity-id' => ServiceProviderDocuments::SIMPLESAMLPHP,
        ]);

        // When
        $tester = self::console(SamlServiceProviderRefreshCommand::NAME);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(
            sprintf('The service provider "%s" is registered from its metadata.', ServiceProviderDocuments::SIMPLESAMLPHP),
            self::flattened($tester),
        );
        static::assertSame(ServiceProviderDocuments::simpleSamlPhp(), self::accepted()?->document);
    }

    /**
     * Section 6.2, forgotten
     */
    #[Test]
    public function forgettingAnEntityIdNothingIsAcceptedForIsRefused(): void
    {
        // When
        $tester = self::console(SamlServiceProviderForgetCommand::NAME, [
            'entity-id' => ServiceProviderDocuments::SIMPLESAMLPHP,
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(
            sprintf('No metadata are accepted for the service provider "%s": nothing is forgotten.', ServiceProviderDocuments::SIMPLESAMLPHP),
            self::flattened($tester),
        );
    }

    /**
     * Section 6.2
     */
    #[Test]
    public function theStepOfTheScheduleRegistersTheServiceProvider(): void
    {
        // Given
        self::publish(ServiceProviderDocuments::simpleSamlPhp());

        // When
        self::service('command.bus', MessageBusInterface::class)->dispatch(new RefreshTheSamlMetadata());

        // Then
        static::assertInstanceOf(AcceptedServiceProviderMetadata::class, self::accepted());
    }

    /**
     * S-6, section 6.2
     */
    #[Test]
    public function aDocumentTheStepOfTheScheduleRefusesIsLoggedAsAnError(): void
    {
        // Given
        self::publish(ServiceProviderDocuments::simpleSamlPhpWithoutEncryptionKey());
        $said = new RecordedMessages();
        /** @var ServiceLocator<MetadataRefresh<covariant PeerInterface>> $roles */
        $roles = new ServiceLocator([
            'beffroi.saml.service_providers.refresh' => static fn (): MetadataRefresh => self::service(
                'beffroi.saml.service_providers.refresh',
                MetadataRefresh::class,
            ),
        ]);
        $step = new RefreshTheSamlMetadataHandler(self::service(TenantProvider::class, TenantProvider::class), $roles, $said);

        // When
        $step(new RefreshTheSamlMetadata());

        // Then
        static::assertSame(
            [sprintf(
                'The metadata of the service provider "%s" are refused, the document accepted kept: The service provider asks for encrypted assertions and its metadata hold no key for encryption (spec/saml.md S-7).',
                ServiceProviderDocuments::SIMPLESAMLPHP,
            )],
            $said->at(LogLevel::ERROR),
        );
    }

    private static function publish(string $document): void
    {
        $kernel = self::$kernel ?? static::fail('The kernel is not booted.');
        $path = $kernel->getCacheDir() . '/saml/simplesamlphp-sp-metadata.xml';
        if (! is_dir(dirname($path))) {
            mkdir(dirname($path), 0o777, true);
        }
        file_put_contents($path, $document);
    }

    private static function accepted(string $entityId = ServiceProviderDocuments::SIMPLESAMLPHP): ?AcceptedMetadata
    {
        self::reload();

        return self::service('test.beffroi.saml_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->find(
                self::tenant(),
                $entityId,
            );
    }

    private static function attackerDocument(): string
    {
        return new Serializer()->serialize(new MetadataWriter()->write(
            new EntityDescriptor(
                ServiceProviderDocuments::SIGNED,
                new DateTimeImmutable(self::FAR_VALID_UNTIL),
                serviceProvider: new ServiceProvider(
                    ServiceProviderDocuments::SIGNED,
                    [MetadataFixtures::certificate('idp')],
                    [MetadataFixtures::certificate('idp')],
                    new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, 'https://attacker.example/acs', 0)]),
                ),
            ),
            new Signing(MetadataFixtures::signingKey('idp')),
        ));
    }
}
