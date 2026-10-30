<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\Registration\KeptRegistration;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\Metadata\AttestedMembers;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadataSourceInterface;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Exception\SectorIdentifierUnavailableException;
use Beffroi\Oidc\Port\SectorIdentifierDocumentFetcherInterface;
use Beffroi\Oidc\Tests\Fixture\FakeSectorIdentifierDocumentFetcher;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Beffroi\Oidc\Tests\Fixture\Registrations;
use Beffroi\Oidc\Tests\Fixture\Subjects;
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

    private const string JWKS_URI = 'https://terminal.example/jwks.json';

    private const string BACKCHANNEL_GRANT = 'urn:openid:params:grant-type:ciba';

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
     * RFC 7591 §3.1.1: what an authorisation put in front of the members the client sent is kept apart from
     * them as well as among them, so that a replacement, read from what the client sends (RFC 7592 §2.2),
     * reads it in front of them again.
     */
    #[Test]
    public function whatAnAuthorisationPutInFrontOfTheMembersIsKeptApart(): void
    {
        // When
        $kept = $this->read(
            [
                'redirect_uris' => [self::REDIRECT_URI],
                'client_name' => 'What the client typed',
            ],
            inFront: [
                new AttestedMembers([
                    'client_name' => 'Invoice reader, attested',
                ]),
            ],
        );

        // Then
        static::assertSame(
            [
                'client_name' => 'Invoice reader, attested',
            ],
            $kept->attested,
        );
    }

    /**
     * And a registration nothing was put in front of keeps nothing apart, which is every mode that reads no
     * statement.
     */
    #[Test]
    public function aRegistrationNothingWasPutInFrontOfKeepsNothingApart(): void
    {
        // When
        $kept = $this->read([
            'redirect_uris' => [self::REDIRECT_URI],
        ]);

        // Then
        static::assertNull($kept->attested);
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
     * RFC 7591 §2 (modules oidcc-refresh-token and -refresh-token-rp-key-rotation): the registration
     * request of the plan carries no "scope" member at all, and what such a client is registered with is
     * the set its tenant wrote, read from the policy that wrote it.
     */
    #[Test]
    public function aRegistrationThatNamesNoScopeTakesWhatTheTenantWrote(): void
    {
        // When
        $kept = $this->read(
            [
                'redirect_uris' => [self::REDIRECT_URI],
            ],
            policy: new ClientRegistrationPolicy('a-mode', defaultScopes: Scopes::parse('openid offline_access')),
        );

        // Then
        static::assertSame(
            [
                'scope' => 'openid offline_access',
            ],
            $kept->assigned,
        );
    }

    /**
     * A client that named its own scopes keeps them, and the policy wrote nothing on it: the row keeps what
     * the policy wrote in front of what the client sent, so a default written over a named scope would
     * outlive the request that refused to take it.
     */
    #[Test]
    public function aRegistrationThatNamesItsOwnScopeKeepsIt(): void
    {
        // When
        $kept = $this->read(
            [
                'redirect_uris' => [self::REDIRECT_URI],
                'scope' => 'openid',
            ],
            policy: new ClientRegistrationPolicy('a-mode', defaultScopes: Scopes::parse('openid offline_access')),
        );

        // Then
        static::assertSame([], $kept->assigned);
        static::assertSame('openid', $kept->metadata['scope']);
    }

    /**
     * Decision 0009: a default set of scopes is held to what the tenant hands out tokens for, like every
     * scope a client registers, so a tenant that writes one it does not announce refuses every registration
     * rather than granting one. The refusal names the policy as the source, there being no client to blame.
     */
    #[Test]
    public function aDefaultSetOfScopesTheTenantDoesNotOfferIsRefused(): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('registers the scope "invoices.read", which this tenant does not hand out tokens for');

        // When
        $this->read(
            [
                'redirect_uris' => [self::REDIRECT_URI],
            ],
            policy: new ClientRegistrationPolicy('a-mode', defaultScopes: Scopes::parse('openid invoices.read')),
        );
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
            'does not list the URI "' . self::REDIRECT_URI . '"',
        ];
    }

    /**
     * CIBA Core §4: a client of the backchannel flow registers no redirection URI, so what its sector is
     * read from is its "jwks_uri", and that is what the document of a sector it claims must list. The
     * document of OIDC Registration §5 holds the "jwks_uris" of its clients as it holds their
     * "redirect_uris", and a client whose keys it does not name has not backed its claim.
     */
    #[Test]
    public function aBackchannelClientPublishesItsKeysInTheDocumentOfItsSector(): void
    {
        // Given
        $documents = new FakeSectorIdentifierDocumentFetcher([self::JWKS_URI, 'https://another-terminal.example/jwks.json']);

        // When
        $kept = $this->read(self::backchannelClaimingASector(), documents: $documents, grants: Grants::servedWithCiba());

        // Then
        static::assertSame([self::SECTOR_IDENTIFIER_URI], array_map(
            static fn (ClientUri $read): string => $read->value,
            $documents->fetched,
        ));
        static::assertSame(self::JWKS_URI, $kept->metadata['jwks_uri']);
    }

    #[Test]
    public function aBackchannelClientWhoseKeysTheDocumentOmitsIsRefused(): void
    {
        // Given
        $documents = new FakeSectorIdentifierDocumentFetcher(['https://another-terminal.example/jwks.json']);

        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('does not list the URI "' . self::JWKS_URI . '"');

        // When
        $this->read(self::backchannelClaimingASector(), documents: $documents, grants: Grants::servedWithCiba());
    }

    /**
     * CIBA Core §4: a client registered for the backchannel grant and for a pairwise "sub" registers a
     * "sector_identifier_uri" or a "jwks_uri", and one that registers neither is refused at registration
     * rather than served a "sub" nobody can compute.
     */
    #[Test]
    public function aBackchannelClientThatSaysItsSectorNoWayIsRefused(): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('CIBA Core section 4');

        // When
        $this->read([
            'grant_types' => [self::BACKCHANNEL_GRANT],
            'backchannel_token_delivery_mode' => 'poll',
            'token_endpoint_auth_method' => 'client_secret_basic',
            'subject_type' => 'pairwise',
        ], grants: Grants::servedWithCiba());
    }

    /**
     * @return array<string, mixed>
     */
    private static function backchannelClaimingASector(): array
    {
        return [
            'grant_types' => [self::BACKCHANNEL_GRANT],
            'backchannel_token_delivery_mode' => 'poll',
            'token_endpoint_auth_method' => 'client_secret_basic',
            'subject_type' => 'pairwise',
            'jwks_uri' => self::JWKS_URI,
            'sector_identifier_uri' => self::SECTOR_IDENTIFIER_URI,
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
     * @param list<ClientMetadataSourceInterface> $inFront what an authorisation put in front of the members
     */
    private function read(
        array $members,
        ?ClientSecretInterface $held = null,
        ?SectorIdentifierDocumentFetcherInterface $documents = null,
        ?ServedGrantsInterface $grants = null,
        ?ClientRegistrationPolicy $policy = null,
        array $inFront = [],
    ): KeptRegistration {
        return Registrations::underThePolicy(
            Registrations::reader(grants: $grants, subjects: Subjects::bothKinds()),
            documents: $documents,
        )->read(Fixtures::tenant(), 'drawn-identifier', $inFront, $members, $policy, $held);
    }
}
