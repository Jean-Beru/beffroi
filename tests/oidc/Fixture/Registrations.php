<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Port\ContentEncryptionAlgorithmsInterface;
use Beffroi\Core\Port\KeyEncryptionAlgorithmsInterface;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\HeldSigning;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Claims\StandardClaimsProvider;
use Beffroi\Oidc\Application\Client\RegisteredClients;
use Beffroi\Oidc\Application\Client\Registration\RegistrationHeldToItsSector;
use Beffroi\Oidc\Application\Client\Registration\RegistrationHeldToTheTenant;
use Beffroi\Oidc\Application\Client\Registration\RegistrationSignedWithHeldKeys;
use Beffroi\Oidc\Application\Client\Registration\RegistrationUnderThePolicy;
use Beffroi\Oidc\Application\Scope\OfferedScopes;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationDeclaredScopes;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Port\ClientSourceInterface;
use Beffroi\Oidc\Port\OfferedScopesInterface;
use Beffroi\Oidc\Port\SectorIdentifierDocumentFetcherInterface;
use Beffroi\Oidc\Application\Client\ClientMetadataReader;
use Beffroi\Oidc\Bridge\Pki\PkiFrameworkCertificateReader;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Beffroi\Oidc\Domain\Client\Metadata\DeclaredMembers;
use Beffroi\Oidc\Domain\Client\Metadata\DeploymentDefaults;
use Beffroi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Beffroi\Oidc\Domain\Client\Metadata\SpecifiedDefaults;
use Beffroi\Oidc\Port\CertificateReaderInterface;
use Beffroi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Beffroi\Oidc\Port\PresentedTokenTypesInterface;
use Beffroi\Oidc\Port\ServedAccessTokenShapesInterface;
use Beffroi\Oidc\Port\ServedAuthorizationDetailTypesInterface;
use Beffroi\Oidc\Port\ServedDeliveryModesInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Beffroi\Oidc\Port\AssignedSubjectTypesInterface;

/**
 * RFC 7591 §2
 */
final class Registrations
{
    public static function reader(
        ?ServedGrantsInterface $grants = null,
        ?ClientAuthenticationMethodsInterface $methods = null,
        ?ServedAccessTokenShapesInterface $shapes = null,
        ?ServedAuthorizationDetailTypesInterface $authorizationDetailTypes = null,
        ?ServedDeliveryModesInterface $deliveryModes = null,
        ?PresentedTokenTypesInterface $tokenTypes = null,
        ?SignatureAlgorithmsInterface $algorithms = null,
        ?CertificateReaderInterface $certificates = null,
        ?KeyEncryptionAlgorithmsInterface $keyEncryption = null,
        ?ContentEncryptionAlgorithmsInterface $contentEncryption = null,
        ?AssignedSubjectTypesInterface $subjects = null,
    ): ClientMetadataReader {
        return new ClientMetadataReader(
            $algorithms ?? Algorithms::all(),
            $methods ?? Methods::all(),
            $grants ?? Grants::served(),
            $shapes ?? Shapes::served(),
            $certificates ?? new PkiFrameworkCertificateReader(),
            $keyEncryption ?? Algorithms::keyEncryption(),
            $contentEncryption ?? Algorithms::contentEncryption(),
            $deliveryModes ?? DeliveryModes::served(),
            $tokenTypes ?? TokenTypes::served(),
            $authorizationDetailTypes ?? AuthorizationDetailTypes::served(),
            $subjects ?? Subjects::ofAProvider(),
        );
    }

    public static function underThePolicy(
        ?ClientMetadataReader $reader = null,
        ?OfferedScopesInterface $scopes = null,
        ?SectorIdentifierDocumentFetcherInterface $documents = null,
    ): RegistrationUnderThePolicy {
        return new RegistrationUnderThePolicy(
            $reader ?? self::reader(),
            new RegistrationHeldToTheTenant($scopes ?? self::offeredScopes()),
            new RegistrationSignedWithHeldKeys(HeldSigning::everyAlgorithm()),
            new RegistrationHeldToItsSector($documents ?? new FakeSectorIdentifierDocumentFetcher(), Sectors::ofAProvider()),
            Secrets::drawer(),
            new FakePasswordHasher(),
        );
    }

    /**
     * OIDC Core §5.4
     */
    public static function offeredScopes(?ClientSourceInterface $clients = null): OfferedScopesInterface
    {
        return new OfferedScopes(
            new StandardClaimsProvider(),
            Grants::served(),
            new RegisteredClients([$clients ?? new InMemoryClientRepository()]),
            new ConfigurationDeclaredScopes(Fixtures::tenant()->slug),
        );
    }

    /**
     * @param array<string, mixed> $members
     */
    public static function declared(array $members): ClientMetadata
    {
        return new ClientMetadata([new DeclaredMembers($members), new DeploymentDefaults()]);
    }

    /**
     * RFC 7591 §2
     *
     * @param array<string, mixed> $members
     */
    public static function registered(array $members): ClientMetadata
    {
        return new ClientMetadata([new RegisteredMembers($members), new SpecifiedDefaults()]);
    }
}
