<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client\Registration;

use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Client\Registration\KeptRegistration;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Domain\Client\HashedClientSecret;
use Heidi\Oidc\Domain\Client\SharedClientSecret;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Exception\InvalidClientMetadataException;
use Heidi\Oidc\Exception\SectorIdentifierUnavailableException;
use Heidi\Oidc\Port\SectorIdentifierDocumentFetcherInterface;
use Heidi\Oidc\Tests\Fixture\FakeSectorIdentifierDocumentFetcher;
use Heidi\Oidc\Tests\Fixture\Registrations;
use Heidi\Oidc\Tests\Fixture\Subjects;
use function array_map;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7591 §3.2.1: the provider assigns a secret exactly when the registered method proves one. The one
 * thing that reads a registration the provider is about to write is where that is decided, so a creation
 * and a replacement decide it the same way.
 */
final class RegistrationUnderThePolicyTest extends TestCase
{
    private const string SECRET = 'a-secret-the-provider-handed-it-of-at-least-32-characters';

    private const string REDIRECT_URI = 'https://rp.example/cb';

    private const string SECTOR_IDENTIFIER_URI = 'https://sector.example/redirect_uris.json';

    #[Test]
    public function aClientWhoseMethodProvesNoSecretIsHandedNone(): void
    {
        // When
        $kept = $this->read([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'none',
        ]);

        // Then
        static::assertNull($kept->secret);
        static::assertNull($kept->drawnSecret);
    }

    #[Test]
    public function aClientWhoseMethodProvesASecretAndHoldsNoneIsHandedOne(): void
    {
        // When
        $kept = $this->read([
            'redirect_uris' => ['https://rp.example/cb'],
        ]);

        // Then
        static::assertIsString($kept->drawnSecret);
        static::assertInstanceOf(HashedClientSecret::class, $kept->secret);
    }

    /**
     * A client that already holds the secret its method proves keeps it: nothing is drawn, so nothing is
     * answered, which is what makes a replacement leave a secret alone (RFC 7592 §2.2).
     */
    #[Test]
    public function aClientThatAlreadyHoldsTheSecretItsMethodProvesKeepsIt(): void
    {
        // Given
        $held = new HashedClientSecret(new FakePasswordHasher()->hash(self::SECRET));

        // When
        $kept = $this->read([
            'redirect_uris' => ['https://rp.example/cb'],
        ], $held);

        // Then
        static::assertSame($held, $kept->secret);
        static::assertNull($kept->drawnSecret);
    }

    /**
     * A secret kept in a shape the registered method does not verify against is no secret for it, so one is
     * drawn: a client that registers the method signing with its secret cannot sign with a hash.
     */
    #[Test]
    public function aClientThatHoldsASecretOfAnotherShapeIsHandedOneItsMethodCanUse(): void
    {
        // Given
        $held = new HashedClientSecret(new FakePasswordHasher()->hash(self::SECRET));

        // When
        $kept = $this->read([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'client_secret_jwt',
        ], $held);

        // Then
        static::assertIsString($kept->drawnSecret);
        static::assertInstanceOf(SharedClientSecret::class, $kept->secret);
    }

    /**
     * Decision 0017: a tenant that has no policy writes nothing on the registration it has none for.
     */
    #[Test]
    public function aTenantWithoutAPolicyWritesNothingOnTheRegistration(): void
    {
        // When
        $kept = $this->read([
            'redirect_uris' => ['https://rp.example/cb'],
        ]);

        // Then
        static::assertSame([], $kept->assigned);
    }

    /**
     * OIDC Registration §5 (module oidcc-registration-sector-bad): a client that claims a sector publishes,
     * on the host of that sector, the array of the redirection URIs of its clients, and every URI it
     * registers is in it. The four ways that claim fails are one refusal, "invalid_client_metadata" naming
     * the member, because a sector a client cannot back is a sector it could have taken from anybody.
     *
     * @param list<string> $document the redirection URIs the document lists
     */
    #[Test]
    #[DataProvider('provideSectorsThatDoNotHold')]
    public function aSectorTheClientCannotBackIsRefused(
        string $sectorIdentifierUri,
        ?string $unreadable,
        array $document,
        string $named,
    ): void {
        // Given
        $documents = new FakeSectorIdentifierDocumentFetcher($document);
        $documents->failure = $unreadable === null ? null : new SectorIdentifierUnavailableException($unreadable);

        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains($named);

        // When
        $this->read([
            'redirect_uris' => [self::REDIRECT_URI],
            'token_endpoint_auth_method' => 'none',
            'subject_type' => 'pairwise',
            'sector_identifier_uri' => $sectorIdentifierUri,
        ], documents: $documents);
    }

    /**
     * @return iterable<string, array{string, string|null, list<string>, string}>
     */
    public static function provideSectorsThatDoNotHold(): iterable
    {
        yield 'a document served in plain HTTP' => [
            'http://sector.example/redirect_uris.json',
            null,
            [self::REDIRECT_URI],
            'must use HTTPS',
        ];

        yield 'a document that redirects' => [
            self::SECTOR_IDENTIFIER_URI,
            'https://sector.example/redirect_uris.json redirects, and no outbound request follows a redirect; publish the document at the URL that is registered.',
            [],
            'no outbound request follows a redirect',
        ];

        yield 'a document that is no JSON array' => [
            self::SECTOR_IDENTIFIER_URI,
            'https://sector.example/redirect_uris.json does not answer the JSON array of redirection URIs of OIDC Registration section 5.',
            [],
            'does not answer the JSON array of redirection URIs',
        ];

        yield 'a document that omits a redirection URI the client registers' => [
            self::SECTOR_IDENTIFIER_URI,
            null,
            ['https://somebody-else.example/cb'],
            'does not list the redirection URI "' . self::REDIRECT_URI . '"',
        ];
    }

    /**
     * The claim held: the document names what the client registers, so the registration is written and the
     * sector is the host the document is served on.
     */
    #[Test]
    public function aSectorTheDocumentBacksIsRegistered(): void
    {
        // Given
        $documents = new FakeSectorIdentifierDocumentFetcher([self::REDIRECT_URI, 'https://another-client.example/cb']);

        // When
        $kept = $this->read([
            'redirect_uris' => [self::REDIRECT_URI],
            'token_endpoint_auth_method' => 'none',
            'subject_type' => 'pairwise',
            'sector_identifier_uri' => self::SECTOR_IDENTIFIER_URI,
        ], documents: $documents);

        // Then
        static::assertSame([self::SECTOR_IDENTIFIER_URI], array_map(
            static fn (ClientUri $read): string => $read->value,
            $documents->fetched,
        ));
        static::assertNull($kept->secret);
    }

    /**
     * A client that registers no "sector_identifier_uri" claims no sector, so nothing is read on its behalf:
     * the provider makes no outbound request on a URL nobody wrote.
     */
    #[Test]
    public function aClientThatClaimsNoSectorHasNothingRead(): void
    {
        // Given
        $documents = new FakeSectorIdentifierDocumentFetcher();

        // When
        $this->read([
            'redirect_uris' => [self::REDIRECT_URI],
            'token_endpoint_auth_method' => 'none',
            'subject_type' => 'pairwise',
        ], documents: $documents);

        // Then
        static::assertSame([], $documents->fetched);
    }

    /**
     * @param array<string, mixed> $members
     */
    private function read(
        array $members,
        ?ClientSecretInterface $held = null,
        ?SectorIdentifierDocumentFetcherInterface $documents = null,
    ): KeptRegistration {
        return Registrations::underThePolicy(
            Registrations::reader(subjects: Subjects::bothKinds()),
            documents: $documents,
        )->read(Fixtures::tenant(), 'drawn-identifier', [], $members, null, $held);
    }
}
