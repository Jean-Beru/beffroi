<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\Registration\KeptRegistration;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\Metadata\AttestedMembers;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadataSourceInterface;
use Beffroi\Oidc\Domain\Client\Metadata\GrantedMembers;
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
 * RFC 7591 §3.2.1
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
     * RFC 7592 §2.2
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
     * RFC 7591 §3.1.1, RFC 7592 §2.2
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
     * RFC 7592 §2.2, Decision 0043
     */
    #[Test]
    public function whatATokenGaveIsKeptOutOfWhatTheClientSent(): void
    {
        // When
        $kept = $this->read(
            [
                'redirect_uris' => [self::REDIRECT_URI],
            ],
            granted: new GrantedMembers([
                'resources' => ['https://api.example/invoices'],
            ]),
        );

        // Then
        static::assertSame(
            [
                'redirect_uris' => [self::REDIRECT_URI],
            ],
            $kept->metadata,
        );
    }

    /**
     * RFC 8693 §2.1, Decision 0043
     */
    #[Test]
    public function aClientATokenGaveTheExchangeToRegistersTheGrantThatExchanges(): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIs('The client "drawn-identifier" declares a token_exchange and no grant that would exchange anything: register one of: urn:ietf:params:oauth:grant-type:token-exchange.');

        // When
        $this->read(
            [
                'redirect_uris' => [self::REDIRECT_URI],
            ],
            grants: Grants::servedWithTokenExchange(),
            granted: new GrantedMembers([
                'token_exchange' => [
                    'subject_token_types' => ['urn:ietf:params:oauth:token-type:access_token'],
                ],
            ]),
        );
    }

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
     * Decision 0017
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
     * RFC 7591 §2
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
     * Decision 0009
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
     * OIDC Registration §5
     *
     * @param list<string> $document
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
            'cannot be read as the JSON array of redirection URIs of OIDC Registration section 5',
        ];

        yield 'a document that is no JSON array' => [
            self::SECTOR_IDENTIFIER_URI,
            'https://sector.example/redirect_uris.json does not answer the JSON array of redirection URIs of OIDC Registration section 5.',
            [],
            'cannot be read as the JSON array of redirection URIs of OIDC Registration section 5',
        ];

        yield 'a document that omits a redirection URI the client registers' => [
            self::SECTOR_IDENTIFIER_URI,
            null,
            ['https://somebody-else.example/cb'],
            'does not list the URI "' . self::REDIRECT_URI . '"',
        ];
    }

    /**
     * CIBA Core §4, OIDC Registration §5
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
     * CIBA Core §4
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
     * @param list<ClientMetadataSourceInterface> $inFront
     */
    private function read(
        array $members,
        ?ClientSecretInterface $held = null,
        ?SectorIdentifierDocumentFetcherInterface $documents = null,
        ?ServedGrantsInterface $grants = null,
        ?ClientRegistrationPolicy $policy = null,
        array $inFront = [],
        ?GrantedMembers $granted = null,
    ): KeptRegistration {
        return Registrations::underThePolicy(
            Registrations::reader(grants: $grants, subjects: Subjects::bothKinds()),
            documents: $documents,
        )->read(Fixtures::tenant(), 'drawn-identifier', $inFront, $members, $policy, $held, $granted);
    }
}
