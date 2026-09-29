<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Port\ContentEncryptionAlgorithmsInterface;
use Heidi\Core\Port\KeyEncryptionAlgorithmsInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Client\RegisteredClients;
use Heidi\Oidc\Application\Client\Registration\RegistrationHeldToItsSector;
use Heidi\Oidc\Application\Client\Registration\RegistrationHeldToTheTenant;
use Heidi\Oidc\Application\Client\Registration\RegistrationUnderThePolicy;
use Heidi\Oidc\Application\Scope\OfferedScopes;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Port\ClientSourceInterface;
use Heidi\Oidc\Port\OfferedScopesInterface;
use Heidi\Oidc\Port\SectorIdentifierDocumentFetcherInterface;
use Heidi\Oidc\Application\Client\ClientMetadataReader;
use Heidi\Oidc\Bridge\Pki\PkiFrameworkCertificateReader;
use Heidi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Heidi\Oidc\Domain\Client\Metadata\DeclaredMembers;
use Heidi\Oidc\Domain\Client\Metadata\DeploymentDefaults;
use Heidi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Heidi\Oidc\Domain\Client\Metadata\SpecifiedDefaults;
use Heidi\Oidc\Port\CertificateReaderInterface;
use Heidi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Heidi\Oidc\Port\PresentedTokenTypesInterface;
use Heidi\Oidc\Port\ServedAccessTokenShapesInterface;
use Heidi\Oidc\Port\ServedAuthorizationDetailTypesInterface;
use Heidi\Oidc\Port\ServedDeliveryModesInterface;
use Heidi\Oidc\Port\ServedGrantsInterface;
use Heidi\Oidc\Port\AssignedSubjectTypesInterface;

/**
 * The reader every registration of the tests goes through, wired with what the provider of the tests is
 * wired with, and the two sets of sources a registration is read from: what a deployment declared, behind
 * its own defaults, and what a client sent, behind those of RFC 7591 §2.
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

    /**
     * The one thing that reads a registration the provider is about to write, wired as the bundle wires
     * it: the reader, what the tenant offers, what the sector of a client has to say of it, and what draws
     * and keeps a secret.
     */
    public static function underThePolicy(
        ?ClientMetadataReader $reader = null,
        ?OfferedScopesInterface $scopes = null,
        ?SectorIdentifierDocumentFetcherInterface $documents = null,
    ): RegistrationUnderThePolicy {
        return new RegistrationUnderThePolicy(
            $reader ?? self::reader(),
            new RegistrationHeldToTheTenant($scopes ?? self::offeredScopes()),
            new RegistrationHeldToItsSector($documents ?? new FakeSectorIdentifierDocumentFetcher()),
            Secrets::drawer(),
            new FakePasswordHasher(),
        );
    }

    /**
     * Every scope the tenant of the tests hands out tokens for: the four of OIDC Core §5.4 and whatever the
     * clients given here registered.
     */
    public static function offeredScopes(?ClientSourceInterface $clients = null): OfferedScopesInterface
    {
        return new OfferedScopes(
            new StandardClaimsProvider(),
            Grants::served(),
            new RegisteredClients([$clients ?? new InMemoryClientRepository()]),
        );
    }

    /**
     * What a deployment wrote in its configuration, behind the defaults a deployment means when it writes
     * nothing.
     *
     * @param array<string, mixed> $members
     */
    public static function declared(array $members): ClientMetadata
    {
        return new ClientMetadata([new DeclaredMembers($members), new DeploymentDefaults()]);
    }

    /**
     * What a client registered, behind the defaults of RFC 7591 §2.
     *
     * @param array<string, mixed> $members
     */
    public static function registered(array $members): ClientMetadata
    {
        return new ClientMetadata([new RegisteredMembers($members), new SpecifiedDefaults()]);
    }
}
