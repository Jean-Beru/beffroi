<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use Beffroi\Bundle\Command\SamlServiceProviderRefreshCommand;
use Beffroi\Bundle\Message\RefreshTheServiceProviderMetadata;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use DateTimeImmutable;
use function dirname;
use function file_put_contents;
use function is_dir;
use function mkdir;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * beffroi/saml, spec/saml.md section 6.2, the acceptance of issue #729: the SimpleSAMLphp service provider the
 * configuration of the test declares (tests/symfony/config/config_test.yml), its assertions encrypted, registered by
 * "beffroi:saml:service-provider:refresh" from its metadata, a file of the deployment, at 2026-09-15T10:00:00Z.
 */
final class ServiceProvidersTest extends ConsoleTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        self::mockTime(new DateTimeImmutable('2026-09-15T10:00:00+00:00'));
    }

    /**
     * The acceptance of issue #729: a SimpleSAMLphp service provider is registered by command from its metadata,
     * the bytes that were read kept (S-8).
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
     * S-6, the acceptance of issue #729: an expired document is refused, and the accepted one kept.
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
     * S-6, the acceptance of issue #729: a document older than the one accepted is refused, and the accepted one
     * kept.
     */
    #[Test]
    public function aDocumentOlderThanTheAcceptedOneIsRefusedAndTheAcceptedOneKept(): void
    {
        // Given
        self::publish(ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-08T00:00:00Z'));
        self::console(SamlServiceProviderRefreshCommand::NAME);
        self::publish(ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'));

        // When
        $tester = self::console(SamlServiceProviderRefreshCommand::NAME, [
            'entity-id' => ServiceProviderDocuments::SIMPLESAMLPHP,
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(
            'The metadata are valid until an earlier instant than the document accepted, so they are older (spec/saml.md S-6).',
            self::flattened($tester),
        );
        static::assertEquals(new DateTimeImmutable('2026-10-08T00:00:00Z'), self::accepted()?->validUntil);
    }

    /**
     * S-7, the acceptance of issue #729: the service provider of the test asks for encryption, and its metadata
     * without an encryption key are refused at its registration.
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
     * S-5: the command reads the metadata of what the configuration declares, and makes no service provider.
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
     * Section 6.2: the step of the schedule runs the same object as the command.
     */
    #[Test]
    public function theStepOfTheScheduleRegistersTheServiceProvider(): void
    {
        // Given
        self::publish(ServiceProviderDocuments::simpleSamlPhp());

        // When
        self::service('command.bus', MessageBusInterface::class)->dispatch(new RefreshTheServiceProviderMetadata());

        // Then
        static::assertInstanceOf(AcceptedMetadata::class, self::accepted());
    }

    /**
     * The file the declaration of the test names, in the cache directory of the kernel of this worker.
     */
    private static function publish(string $document): void
    {
        $kernel = self::$kernel ?? static::fail('The kernel is not booted.');
        $path = $kernel->getCacheDir() . '/saml/simplesamlphp-sp-metadata.xml';
        if (! is_dir(dirname($path))) {
            mkdir(dirname($path), 0o777, true);
        }
        file_put_contents($path, $document);
    }

    private static function accepted(): ?AcceptedMetadata
    {
        self::reload();

        return self::service('test.beffroi.saml_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->find(
                self::tenant(),
                ServiceProviderDocuments::SIMPLESAMLPHP,
            );
    }
}
