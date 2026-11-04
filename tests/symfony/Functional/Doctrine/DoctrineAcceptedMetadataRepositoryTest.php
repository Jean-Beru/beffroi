<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\CanForgetAcceptedMetadataInterface;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use DateTimeImmutable;
use LogicException;
use function sprintf;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml spec/saml.md section 6.2 steps 6 and 7, S-42, S-8
 */
final class DoctrineAcceptedMetadataRepositoryTest extends DatabaseTestCase
{
    private const string SIGNED = 'https://sp.example.org/saml';

    private const string BOTH = 'https://saml.acme.example/metadata';

    /**
     * Section 6.2 step 7
     */
    #[Test]
    public function theFirstDocumentOfAServiceProviderIsRegistered(): void
    {
        // When
        $registered = self::repository()->register(self::accepted(ServiceProviderDocuments::SIMPLESAMLPHP, ServiceProviderDocuments::simpleSamlPhp()));
        self::reload();

        // Then
        static::assertTrue($registered);
        static::assertSame(
            ServiceProviderDocuments::simpleSamlPhp(),
            self::repository()->find(self::tenant(), ServiceProviderDocuments::SIMPLESAMLPHP)?->document,
        );
    }

    /**
     * Section 6.2 step 6
     */
    #[Test]
    public function aServiceProviderRegisteredFirstByAnotherProcessKeepsItsRow(): void
    {
        // Given
        self::repository()->register(self::accepted(ServiceProviderDocuments::SIMPLESAMLPHP, ServiceProviderDocuments::simpleSamlPhp()));

        // When
        $registered = self::repository()
            ->register(self::accepted(
                ServiceProviderDocuments::SIMPLESAMLPHP,
                ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-08T00:00:00Z'),
            ));
        self::reload();

        // Then
        static::assertFalse($registered);
        static::assertSame(
            ServiceProviderDocuments::simpleSamlPhp(),
            self::repository()->find(self::tenant(), ServiceProviderDocuments::SIMPLESAMLPHP)?->document,
        );
    }

    /**
     * Section 6.2
     */
    #[Test]
    public function aRegistrationThatLostTheRaceLeavesTheStoreUsable(): void
    {
        // Given
        self::repository()->register(self::accepted(ServiceProviderDocuments::SIMPLESAMLPHP, ServiceProviderDocuments::simpleSamlPhp()));
        self::repository()->register(self::accepted(ServiceProviderDocuments::SIMPLESAMLPHP, ServiceProviderDocuments::simpleSamlPhp()));

        // When
        $registered = self::repository()
            ->register(self::accepted(self::SIGNED, ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z'))));

        // Then
        static::assertTrue($registered);
        static::assertInstanceOf(AcceptedServiceProviderMetadata::class, self::repository()->find(self::tenant(), self::SIGNED));
    }

    /**
     * S-42, S-8
     */
    #[Test]
    public function anEntityIdOfBothRolesIsForgottenInOneOnly(): void
    {
        // Given
        self::repository()->register(self::accepted(self::BOTH, ServiceProviderDocuments::simpleSamlPhp()));
        self::upstream()
            ->register(new AcceptedUpstreamMetadata(Uuid::v7(), self::tenant(), self::BOTH, IdentityProviderDocuments::simpleSamlPhp(), null, self::now()));
        self::reload();
        $serviceProvider = self::repository()->find(self::tenant(), self::BOTH) ?? static::fail('The service provider is not registered.');

        // When
        self::service('test.beffroi.saml_accepted_metadata', CanForgetAcceptedMetadataInterface::class)->forget($serviceProvider);
        self::reload();

        // Then
        static::assertNull(self::repository()->find(self::tenant(), self::BOTH));
        static::assertSame(IdentityProviderDocuments::simpleSamlPhp(), self::upstream()->find(self::tenant(), self::BOTH)?->document);
    }

    /**
     * S-8
     */
    #[Test]
    public function theRepositoryOfOneRoleRefusesTheRowOfTheOther(): void
    {
        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The repository of %s is handed a %s, the row of another role.',
            AcceptedServiceProviderMetadata::class,
            AcceptedUpstreamMetadata::class,
        ));

        // When
        self::repository()
            ->register(new AcceptedUpstreamMetadata(Uuid::v7(), self::tenant(), self::BOTH, IdentityProviderDocuments::simpleSamlPhp(), null, self::now()));
    }

    private static function accepted(string $entityId, string $document): AcceptedMetadata
    {
        return new AcceptedServiceProviderMetadata(Uuid::v7(), self::tenant(), $entityId, $document, null, self::now());
    }

    private static function repository(): AcceptedMetadataRepositoryInterface
    {
        return self::service('test.beffroi.saml_accepted_metadata', AcceptedMetadataRepositoryInterface::class);
    }

    private static function upstream(): AcceptedMetadataRepositoryInterface
    {
        return self::service('test.beffroi.saml_upstream_accepted_metadata', AcceptedMetadataRepositoryInterface::class);
    }
}
