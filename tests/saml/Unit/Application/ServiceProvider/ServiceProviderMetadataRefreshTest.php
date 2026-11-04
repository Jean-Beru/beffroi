<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\ServiceProvider;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Application\Metadata\AcceptedMetadataForgetting;
use Beffroi\Saml\Application\Metadata\MetadataRefreshment;
use Beffroi\Saml\Application\Metadata\MetadataRefresh;
use Beffroi\Saml\Application\ServiceProvider\ServiceProviderRole;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataReader;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;
use Beffroi\Saml\Tests\Fixture\FixedClaims;
use Beffroi\Saml\Tests\Fixture\FixedMetadataFetcher;
use Beffroi\Saml\Tests\Fixture\InMemoryAcceptedMetadata;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md section 6.2
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
     * S-8
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
     * Section 6.2 step 6
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
     * Section 6.2 step 6
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
     * S-6
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
     * S-6
     */
    #[Test]
    public function aSignedDocumentOlderThanTheAcceptedOneIsRefusedAndTheAcceptedOneKept(): void
    {
        // Given
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-08T00:00:00Z')));
        $this->refreshSigned();
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')));

        // When
        $refreshment = $this->refreshSigned();

        // Then
        static::assertTrue($refreshment->refused);
        static::assertStringEndsWith(
            'The metadata are valid until an earlier instant than the document accepted, so they are older (spec/saml.md S-6).',
            $refreshment->what,
        );
        static::assertEquals(new DateTimeImmutable('2026-10-08T00:00:00Z'), $this->acceptedSigned()->validUntil);
        static::assertSame(1, $this->accepted->saves);
    }

    /**
     * S-6, finding B-1 of the security review of 20 October 2026
     */
    #[Test]
    #[DataProvider('provideDocumentsTrustedByTheirChannel')]
    public function aDocumentTrustedByItsChannelReplacesTheAcceptedOneWhateverItsValidUntil(
        string $accepted,
        string $read,
        ?DateTimeImmutable $validUntil,
    ): void {
        // Given
        $this->fetcher->answer(self::LOCATION, $accepted);
        $this->refreshSimpleSamlPhp();
        $this->fetcher->answer(self::LOCATION, $read);

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertSame(\sprintf('The metadata of the service provider "%s" are refreshed.', ServiceProviderDocuments::SIMPLESAMLPHP), $refreshment->what);
        static::assertSame($read, $this->acceptedSimpleSamlPhp()->document);
        static::assertEquals($validUntil, $this->acceptedSimpleSamlPhp()->validUntil);
    }

    /**
     * @return iterable<string, array{string, string, ?DateTimeImmutable}>
     */
    public static function provideDocumentsTrustedByTheirChannel(): iterable
    {
        yield 'none after a far validUntil' => [
            ServiceProviderDocuments::simpleSamlPhpValidUntil('2099-01-01T00:00:00Z'),
            ServiceProviderDocuments::simpleSamlPhp(),
            null,
        ];
        yield 'an earlier validUntil' => [
            ServiceProviderDocuments::simpleSamlPhpValidUntil('2099-01-01T00:00:00Z'),
            ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'),
            new DateTimeImmutable('2026-10-01T00:00:00Z'),
        ];
    }

    /**
     * S-6, section 6.2, forgotten
     */
    #[Test]
    public function aServiceProviderForgottenIsRegisteredAgainFromAnOlderSignedDocument(): void
    {
        // Given
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-08T00:00:00Z')));
        $this->refreshSigned();
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')));
        new AcceptedMetadataForgetting($this->accepted, $this->accepted)->forget($this->tenant, ServiceProviderDocuments::SIGNED);

        // When
        $refreshment = $this->refreshSigned();

        // Then
        static::assertSame(\sprintf('The service provider "%s" is registered from its metadata.', ServiceProviderDocuments::SIGNED), $refreshment->what);
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), $this->acceptedSigned()->validUntil);
    }

    /**
     * S-7
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
     * S-7
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
     * S-7
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
     * S-11
     */
    #[Test]
    public function aServiceProviderThatSignsWithoutAKeyInItsMetadataIsRefusedAtRegistration(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::entra());

        // When
        $refreshment = $this->refreshEntra(signs: true);

        // Then
        static::assertTrue($refreshment->refused);
        static::assertStringEndsWith(
            'The requests of the service provider need a signature and its metadata hold no key for signing (spec/saml.md S-11).',
            $refreshment->what,
        );
        static::assertNull($this->accepted->find($this->tenant, ServiceProviderDocuments::ENTRA));
    }

    /**
     * S-11, S-9
     */
    #[Test]
    public function aServiceProviderDeclaredUnsignedNeedsNoKeyInItsMetadata(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::entra());

        // When
        $refreshment = $this->refreshEntra(signs: false);

        // Then
        static::assertFalse($refreshment->refused, $refreshment->what);
    }

    /**
     * S-11, S-9
     */
    #[Test]
    public function aServiceProviderDeclaredUnsignedWhoseMetadataSayItSignsIsRefusedWithoutAKey(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::entraSigningItsRequests());

        // When
        $refreshment = $this->refreshEntra(signs: false);

        // Then
        static::assertTrue($refreshment->refused);
        static::assertNull($this->accepted->find($this->tenant, ServiceProviderDocuments::ENTRA));
    }

    /**
     * S-11
     */
    #[Test]
    public function aServiceProviderThatSignsWithAKeyInItsMetadataIsRegistered(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertFalse($refreshment->refused, $refreshment->what);
    }

    /**
     * S-11
     */
    #[Test]
    public function aRefreshThatDropsTheSigningKeyIsRefused(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());
        $this->refreshSimpleSamlPhp();
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpWithoutSigningKey());

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertTrue($refreshment->refused);
        static::assertSame(ServiceProviderDocuments::simpleSamlPhp(), $this->acceptedSimpleSamlPhp()->document);
    }

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
     * S-5
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
     * Section 6.2 step 2
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
     * S-5
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
     * S-5
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
        static::assertInstanceOf(AcceptedServiceProviderMetadata::class, $this->accepted->find($this->tenant, ServiceProviderDocuments::SIGNED));
    }

    /**
     * Section 6.2
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
     * Section 6.2 step 6
     */
    #[Test]
    public function aServiceProviderRegisteredByAnotherProcessMeanwhileIsSkipped(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-08T00:00:00Z'));
        $theOther = new AcceptedServiceProviderMetadata(
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
     * Section 6.2
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
        static::assertInstanceOf(AcceptedServiceProviderMetadata::class, $this->accepted->find($this->tenant, ServiceProviderDocuments::SIGNED));
    }

    /**
     * Section 6.2, M-16
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

    private function refreshEntra(bool $signs): MetadataRefreshment
    {
        return $this->refresh([
            ServiceProviderDocuments::ENTRA => [
                'metadata' => self::LOCATION,
                'signs_authn_requests' => $signs,
            ],
        ])->refreshAll($this->tenant)[0];
    }

    private function refreshSigned(): MetadataRefreshment
    {
        return $this->refresh([
            ServiceProviderDocuments::SIGNED => [
                'metadata' => self::SIGNED_LOCATION,
                'metadata_signers' => [ServiceProviderDocuments::signer()->base64],
            ],
        ])->refreshAll($this->tenant)[0];
    }

    private function acceptedSigned(): AcceptedMetadata
    {
        return $this->accepted->find($this->tenant, ServiceProviderDocuments::SIGNED) ?? static::fail('Nothing is accepted.');
    }

    private function acceptedSimpleSamlPhp(): AcceptedMetadata
    {
        return $this->accepted->find($this->tenant, ServiceProviderDocuments::SIMPLESAMLPHP) ?? static::fail('Nothing is accepted.');
    }

    /**
     * @param array<string, array<string, mixed>> $definitions
     *
     * @return MetadataRefresh<ServiceProvider>
     */
    private function refresh(array $definitions): MetadataRefresh
    {
        return new MetadataRefresh(
            new ServiceProviderRole(
                new ConfigurationServiceProviders($this->tenant->slug, $definitions, new FixedClaims()),
                new ModelServiceProviderMetadataReader($this->clock),
            ),
            $this->fetcher,
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
