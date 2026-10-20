<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\ServiceProvider;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Application\ServiceProvider\AcceptedMetadataForgetting;
use Beffroi\Saml\Application\ServiceProvider\MetadataRefreshment;
use Beffroi\Saml\Application\ServiceProvider\ServiceProviderMetadataRefresh;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataReader;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedMetadata;
use Beffroi\Saml\Tests\Fixture\FixedMetadataFetcher;
use Beffroi\Saml\Tests\Fixture\InMemoryAcceptedMetadata;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md section 6.2: the metadata of a service provider registered the first time and refreshed every time
 * after, by the declarations of the configuration, the reader of the model and a fetcher of the test, at
 * 2026-09-15T10:00:00Z.
 */
final class ServiceProviderMetadataRefreshTest extends TestCase
{
    private const string LOCATION = 'https://sp.example.com/saml/metadata';

    private const string SIGNED_LOCATION = '/srv/saml/signed-sp-metadata.xml';

    private Tenant $tenant;

    private MockClock $clock;

    private FixedMetadataFetcher $fetcher;

    private InMemoryAcceptedMetadata $accepted;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clock = new MockClock(Fixtures::now());
        $this->fetcher = new FixedMetadataFetcher();
        $this->accepted = new InMemoryAcceptedMetadata();
    }

    /**
     * The acceptance of issue #729: a SimpleSAMLphp service provider is registered from its metadata, the bytes that
     * were read kept (S-8).
     */
    #[Test]
    public function aServiceProviderIsRegisteredFromItsMetadata(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertFalse($refreshment->refused, $refreshment->what);
        static::assertSame(\sprintf('The service provider "%s" is registered from its metadata.', ServiceProviderDocuments::SIMPLESAMLPHP), $refreshment->what);
        $accepted = $this->acceptedSimpleSamlPhp();
        static::assertSame(ServiceProviderDocuments::simpleSamlPhp(), $accepted->document);
        static::assertNull($accepted->validUntil);
        static::assertEquals(Fixtures::now(), $accepted->acceptedAt);
        static::assertSame($this->tenant, $accepted->tenant);
    }

    /**
     * Section 6.2 step 6: the same bytes read again write nothing.
     */
    #[Test]
    public function theSameDocumentReadAgainWritesNothing(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());
        $this->refreshSimpleSamlPhp();

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertFalse($refreshment->refused);
        static::assertSame(
            \sprintf('The metadata of the service provider "%s" are the ones accepted already.', ServiceProviderDocuments::SIMPLESAMLPHP),
            $refreshment->what,
        );
        static::assertSame(1, $this->accepted->saves);
    }

    /**
     * Section 6.2 step 6: a newer document takes the place of the accepted one.
     */
    #[Test]
    public function aNewerDocumentIsAccepted(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'));
        $this->refreshSimpleSamlPhp();
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-08T00:00:00Z'));
        $this->clock->sleep(3600);

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertSame(\sprintf('The metadata of the service provider "%s" are refreshed.', ServiceProviderDocuments::SIMPLESAMLPHP), $refreshment->what);
        $accepted = $this->acceptedSimpleSamlPhp();
        static::assertEquals(new DateTimeImmutable('2026-10-08T00:00:00Z'), $accepted->validUntil);
        static::assertEquals(Fixtures::now()->modify('+1 hour'), $accepted->acceptedAt);
        static::assertSame(2, $this->accepted->saves);
    }

    /**
     * S-6, the acceptance of issue #729: an expired document is refused, the accepted one kept.
     */
    #[Test]
    public function anExpiredDocumentIsRefusedAndTheAcceptedOneKept(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'));
        $this->refreshSimpleSamlPhp();
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-09-15T09:00:00Z'));

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertTrue($refreshment->refused);
        static::assertSame(
            \sprintf(
                'The metadata of the service provider "%s" are refused, the document accepted kept: The metadata is past its validUntil (M-7).',
                ServiceProviderDocuments::SIMPLESAMLPHP,
            ),
            $refreshment->what,
        );
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), $this->acceptedSimpleSamlPhp()->validUntil);
        static::assertSame(1, $this->accepted->saves);
    }

    /**
     * S-6, the acceptance of issue #729: a document older than the one accepted is refused, the accepted one kept.
     */
    #[Test]
    public function aDocumentOlderThanTheAcceptedOneIsRefusedAndTheAcceptedOneKept(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-08T00:00:00Z'));
        $this->refreshSimpleSamlPhp();
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'));

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertTrue($refreshment->refused);
        static::assertStringEndsWith(
            'The metadata are valid until an earlier instant than the document accepted, so they are older (spec/saml.md S-6).',
            $refreshment->what,
        );
        static::assertEquals(new DateTimeImmutable('2026-10-08T00:00:00Z'), $this->acceptedSimpleSamlPhp()->validUntil);
        static::assertSame(1, $this->accepted->saves);
    }

    /**
     * S-6, section 6.2, forgotten: a service provider that went back to a document without validUntil after one that
     * had one is registered again from it once an operator forgot the document accepted.
     */
    #[Test]
    public function aServiceProviderForgottenIsRegisteredAgainFromADocumentWithoutValidUntil(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-08T00:00:00Z'));
        $this->refreshSimpleSamlPhp();
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());
        new AcceptedMetadataForgetting($this->accepted, $this->accepted)->forget($this->tenant, ServiceProviderDocuments::SIMPLESAMLPHP);

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertSame(\sprintf('The service provider "%s" is registered from its metadata.', ServiceProviderDocuments::SIMPLESAMLPHP), $refreshment->what);
        static::assertNull($this->acceptedSimpleSamlPhp()->validUntil);
    }

    /**
     * S-7, the acceptance of issue #729: a service provider asking for encryption without an encryption key in its
     * metadata is refused at registration.
     */
    #[Test]
    public function aServiceProviderAskingForEncryptionWithoutAKeyIsRefusedAtRegistration(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpWithoutEncryptionKey());

        // When
        $refreshment = $this->refreshSimpleSamlPhp(encrypt: true);

        // Then
        static::assertTrue($refreshment->refused);
        static::assertStringEndsWith(
            'The service provider asks for encrypted assertions and its metadata hold no key for encryption (spec/saml.md S-7).',
            $refreshment->what,
        );
        static::assertNull($this->accepted->find($this->tenant, ServiceProviderDocuments::SIMPLESAMLPHP));
    }

    /**
     * S-7: a service provider asking for encryption whose metadata hold a key for it is registered.
     */
    #[Test]
    public function aServiceProviderAskingForEncryptionWithAKeyIsRegistered(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());

        // When
        $refreshment = $this->refreshSimpleSamlPhp(encrypt: true);

        // Then
        static::assertFalse($refreshment->refused, $refreshment->what);
    }

    /**
     * S-7: a refresh that drops the key for encryption is refused, the accepted document kept.
     */
    #[Test]
    public function aRefreshThatDropsTheEncryptionKeyIsRefused(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());
        $this->refreshSimpleSamlPhp(encrypt: true);
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpWithoutEncryptionKey());

        // When
        $refreshment = $this->refreshSimpleSamlPhp(encrypt: true);

        // Then
        static::assertTrue($refreshment->refused);
        static::assertSame(ServiceProviderDocuments::simpleSamlPhp(), $this->acceptedSimpleSamlPhp()->document);
    }

    /**
     * A service provider that does not ask for encryption needs no key for it.
     */
    #[Test]
    public function aServiceProviderThatAsksForNoEncryptionNeedsNoKeyForIt(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpWithoutEncryptionKey());

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertFalse($refreshment->refused, $refreshment->what);
    }

    /**
     * S-5: the metadata of another entity than the one declared are refused.
     */
    #[Test]
    public function theMetadataOfAnotherEntityAreRefused(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());
        $refresh = $this->refresh([
            'https://sp.example.com/saml' => [
                'metadata' => self::LOCATION,
            ],
        ]);

        // When
        $refreshment = $refresh->refreshAll($this->tenant)[0];

        // Then
        static::assertTrue($refreshment->refused);
        static::assertSame(
            'The metadata of the service provider "https://sp.example.com/saml" are refused, the document accepted kept: The metadata name another entity than the service provider declared (spec/saml.md S-5).',
            $refreshment->what,
        );
        static::assertSame(0, $this->accepted->saves);
    }

    /**
     * Section 6.2 step 2: a location that cannot be read is a refusal, returned rather than thrown.
     */
    #[Test]
    public function aLocationThatCannotBeReadIsRefused(): void
    {
        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertTrue($refreshment->refused);
        static::assertStringEndsWith('The location answers nothing.', $refreshment->what);
    }

    /**
     * S-5: a declaration that pins a signer has its metadata read signed, and a document of the channel alone is
     * refused.
     */
    #[Test]
    public function aDeclarationThatPinsASignerRefusesAnUnsignedDocument(): void
    {
        // Given
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'));
        $refresh = $this->refresh([
            ServiceProviderDocuments::SIMPLESAMLPHP => [
                'metadata' => self::SIGNED_LOCATION,
                'metadata_signers' => [ServiceProviderDocuments::signer()->base64],
            ],
        ]);

        // When
        $refreshment = $refresh->refreshAll($this->tenant)[0];

        // Then
        static::assertTrue($refreshment->refused);
        static::assertStringEndsWith('The metadata carries no ds:Signature as the first child of its root (M-2).', $refreshment->what);
    }

    /**
     * S-5: a document signed by the pinned key registers its service provider.
     */
    #[Test]
    public function aDocumentSignedByThePinnedKeyIsRegistered(): void
    {
        // Given
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')));
        $refresh = $this->refresh([
            ServiceProviderDocuments::SIGNED => [
                'metadata' => self::SIGNED_LOCATION,
                'metadata_signers' => [ServiceProviderDocuments::signer()->base64],
            ],
        ]);

        // When
        $refreshment = $refresh->refreshAll($this->tenant)[0];

        // Then
        static::assertFalse($refreshment->refused, $refreshment->what);
        static::assertInstanceOf(AcceptedMetadata::class, $this->accepted->find($this->tenant, ServiceProviderDocuments::SIGNED));
    }

    /**
     * Section 6.2: every service provider the tenant declares is read, whatever one of them answers.
     */
    #[Test]
    public function everyServiceProviderIsReadWhateverOneOfThemAnswers(): void
    {
        // Given
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')));
        $refresh = $this->refresh([
            ServiceProviderDocuments::SIMPLESAMLPHP => [
                'metadata' => self::LOCATION,
            ],
            ServiceProviderDocuments::SIGNED => [
                'metadata' => self::SIGNED_LOCATION,
                'metadata_signers' => [ServiceProviderDocuments::signer()->base64],
            ],
        ]);

        // When
        $refreshments = $refresh->refreshAll($this->tenant);

        // Then
        static::assertSame(
            [
                [ServiceProviderDocuments::SIMPLESAMLPHP, true],
                [ServiceProviderDocuments::SIGNED,        false],
            ],
            \array_map(static fn (MetadataRefreshment $refreshment): array => [$refreshment->entityId, $refreshment->refused], $refreshments),
        );
    }

    /**
     * Section 6.2 step 6: another process, the console and the hourly step at the same minute, registered the service
     * provider between the reading of the accepted document and the write; the unique index keeps its row, and this
     * reading is skipped rather than refused.
     */
    #[Test]
    public function aServiceProviderRegisteredByAnotherProcessMeanwhileIsSkipped(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-08T00:00:00Z'));
        $theOther = new AcceptedMetadata(
            Uuid::v7(),
            $this->tenant,
            ServiceProviderDocuments::SIMPLESAMLPHP,
            ServiceProviderDocuments::simpleSamlPhp(),
            null,
            Fixtures::now(),
        );
        $this->accepted->registeredMeanwhile($theOther);

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertFalse($refreshment->refused);
        static::assertSame(
            \sprintf(
                'The service provider "%s" was registered by another process meanwhile; this reading is skipped.',
                ServiceProviderDocuments::SIMPLESAMLPHP,
            ),
            $refreshment->what,
        );
        static::assertSame($theOther, $this->acceptedSimpleSamlPhp());
    }

    /**
     * Section 6.2: a service provider whose reading throws what no rule refuses, a store or a fetcher that fails, does
     * not stop the ones declared after it.
     */
    #[Test]
    public function aServiceProviderThatFailsDoesNotStopTheNextOne(): void
    {
        // Given
        $this->fetcher->fail(self::LOCATION, new RuntimeException('The store is gone.'));
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')));
        $refresh = $this->refresh([
            ServiceProviderDocuments::SIMPLESAMLPHP => [
                'metadata' => self::LOCATION,
            ],
            ServiceProviderDocuments::SIGNED => [
                'metadata' => self::SIGNED_LOCATION,
                'metadata_signers' => [ServiceProviderDocuments::signer()->base64],
            ],
        ]);

        // When
        $refreshments = $refresh->refreshAll($this->tenant);

        // Then
        static::assertSame(
            [
                [ServiceProviderDocuments::SIMPLESAMLPHP, true],
                [ServiceProviderDocuments::SIGNED,        false],
            ],
            \array_map(static fn (MetadataRefreshment $refreshment): array => [$refreshment->entityId, $refreshment->refused], $refreshments),
        );
        static::assertInstanceOf(AcceptedMetadata::class, $this->accepted->find($this->tenant, ServiceProviderDocuments::SIGNED));
    }

    /**
     * Section 6.2, M-16: a failure is named by the class of what was thrown, never by its message, which may carry a
     * value of the document or of a query.
     */
    #[Test]
    public function aFailureIsNamedByItsClassAndNotByItsMessage(): void
    {
        // Given
        $this->fetcher->fail(self::LOCATION, new RuntimeException('INSERT INTO beffroi_saml_service_provider VALUES (grace.hopper@sp.example.org)'));

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertTrue($refreshment->refused);
        static::assertSame(
            \sprintf(
                'The metadata of the service provider "%s" could not be refreshed, the document accepted kept: RuntimeException was thrown.',
                ServiceProviderDocuments::SIMPLESAMLPHP,
            ),
            $refreshment->what,
        );
    }

    /**
     * The declarations are those of one tenant: another has nothing to refresh.
     */
    #[Test]
    public function anotherTenantHasNothingToRefresh(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());

        // When
        $refreshments = $this->refresh(self::simpleSamlPhpDeclaration(false))->refreshAll(Fixtures::tenant('other'));

        // Then
        static::assertSame([], $refreshments);
    }

    private function refreshSimpleSamlPhp(bool $encrypt = false): MetadataRefreshment
    {
        return $this->refresh(self::simpleSamlPhpDeclaration($encrypt))->refreshAll($this->tenant)[0];
    }

    private function acceptedSimpleSamlPhp(): AcceptedMetadata
    {
        return $this->accepted->find($this->tenant, ServiceProviderDocuments::SIMPLESAMLPHP) ?? static::fail('Nothing is accepted.');
    }

    /**
     * @param array<string, array<string, mixed>> $definitions
     */
    private function refresh(array $definitions): ServiceProviderMetadataRefresh
    {
        return new ServiceProviderMetadataRefresh(
            new ConfigurationServiceProviders($this->tenant->slug, $definitions),
            $this->fetcher,
            new ModelServiceProviderMetadataReader($this->clock),
            $this->accepted,
            $this->clock,
        );
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private static function simpleSamlPhpDeclaration(bool $encrypt): array
    {
        return [
            ServiceProviderDocuments::SIMPLESAMLPHP => [
                'metadata' => self::LOCATION,
                'encrypt_assertions' => $encrypt,
            ],
        ];
    }
}
