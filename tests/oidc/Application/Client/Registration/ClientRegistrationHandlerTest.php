<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use DateInterval;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\ClientIdentifierDrawer;
use Beffroi\Oidc\Application\Client\RegisteredClients;
use Beffroi\Oidc\Application\Client\Registration\ClientRegistrationHandler;
use Beffroi\Oidc\Application\Client\Registration\InitialAccessTokenAuthorization;
use Beffroi\Oidc\Application\Client\Registration\OpenRegistrationAuthorization;
use Beffroi\Oidc\Application\Client\Registration\RegistrationAuthorizations;
use Beffroi\Oidc\Application\Client\Registration\SoftwareStatementAuthorization;
use Beffroi\Oidc\Application\Client\Registration\SoftwareStatementVerifier;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientStore;
use Beffroi\Oidc\Bridge\InMemory\InMemoryInitialAccessTokenRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemorySoftwareStatementReplayGuard;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Client\Registration\ClientInformationResponse;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\ClientRegistrationNotOfferedException;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Exception\UnauthorizedRegistrationException;
use Beffroi\Oidc\Exception\UnreadableClientMetadataException;
use Beffroi\Oidc\Port\ClientRegistrationPolicyInterface;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\Policies;
use Beffroi\Oidc\Tests\Fixture\RegistrationPolicies;
use Beffroi\Oidc\Tests\Fixture\Registrations;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Tests\Fixture\SoftwareStatements;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §3.1, Decision 0009
 */
final class ClientRegistrationHandlerTest extends TestCase
{
    private const string TOKEN = 'a-value-the-tenant-handed-out';

    private Tenant $tenant;

    private InMemoryInitialAccessTokenRepository $tokens;

    private InMemoryClientStore $store;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->tokens = new InMemoryInitialAccessTokenRepository();
        $this->store = new InMemoryClientStore();
    }

    /**
     * Decision 0009
     */
    #[Test]
    public function aTenantThatRegistersNobodyHasNoEndpoint(): void
    {
        // Given
        $this->issue();

        // Then
        $this->expectException(ClientRegistrationNotOfferedException::class);
        $this->expectExceptionMessageIs('This tenant registers no client (decision 0009).');

        // When
        $this->handle(self::request(), RegistrationPolicies::closed());
    }

    #[Test]
    public function itAnswersTheIdentifierItDrewAndWhatItRegistered(): void
    {
        // Given
        $this->issue();

        // When
        $response = $this->handle(self::request());

        // Then
        static::assertSame($response->record->clientId, $response->parameters()['client_id']);
        static::assertSame(['https://rp.example/cb'], $response->parameters()['redirect_uris']);
    }

    /**
     * RFC 7591 §3.2.1
     */
    #[Test]
    public function aClientWhoseMethodProvesASecretIsHandedOne(): void
    {
        // Given
        $this->issue();

        // When
        $response = $this->handle(self::request());

        // Then
        static::assertIsString($response->secret);
        static::assertInstanceOf(HashedClientSecret::class, $response->record->secret);
    }

    #[Test]
    public function aPublicClientIsHandedNoSecret(): void
    {
        // Given
        $this->issue();

        // When
        $response = $this->handle(self::request([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'none',
        ]));

        // Then
        static::assertNull($response->secret);
        static::assertNull($response->record->secret);
    }

    /**
     * OIDC Core §9
     */
    #[Test]
    public function aClientThatSignsWithItsSecretKeepsItWhole(): void
    {
        // Given
        $this->issue();

        // When
        $response = $this->handle(self::request([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'client_secret_jwt',
        ]));

        // Then
        static::assertInstanceOf(SharedClientSecret::class, $response->record->secret);
    }

    /**
     * Decision 0017
     */
    #[Test]
    public function thePolicyWritesThePkceExemptionOnAConfidentialClient(): void
    {
        // Given
        $this->issue();

        // When
        $response = $this->handle(self::request(), RegistrationPolicies::controlled(true));

        // Then
        static::assertSame(
            [
                'requires_pkce' => false,
            ],
            $response->record->assigned,
        );
    }

    /**
     * Decision 0017, RFC 9700 §2.1.1
     */
    #[Test]
    public function aPublicClientIsNeverExempted(): void
    {
        // Given
        $this->issue();

        // When
        $response = $this->handle(self::request([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'none',
        ]), RegistrationPolicies::controlled(true));

        // Then
        static::assertSame([], $response->record->assigned);
    }

    #[Test]
    public function theRowKeepsWhatTheClientSent(): void
    {
        // Given
        $this->issue();
        $members = [
            'redirect_uris' => ['https://rp.example/cb'],
            'client_name' => 'A client nobody declared',
        ];

        // When
        $this->handle(self::request($members));

        // Then
        static::assertSame($members, $this->store->records[0]->metadata);
    }

    #[Test]
    public function aRequestThatAuthorisesNothingRegistersNothing(): void
    {
        // Given
        $this->issue();

        // Then
        $this->expectException(UnauthorizedRegistrationException::class);

        // When
        $this->handle(new RegistrationRequest([
            'redirect_uris' => ['https://rp.example/cb'],
        ]));
    }

    /**
     * RFC 7591 §1.3, Decision 0009
     */
    #[Test]
    public function aTenantWhosePolicyIsOpenRegistersARequestThatPresentsNothing(): void
    {
        // When
        $response = $this->handle(new RegistrationRequest([
            'redirect_uris' => ['https://rp.example/cb'],
        ]), RegistrationPolicies::open());

        // Then
        static::assertSame(['https://rp.example/cb'], $response->parameters()['redirect_uris']);
    }

    /**
     * RFC 7591 §1.2
     */
    #[Test]
    public function theTokenIsSpentEvenWhenTheMetadataThatFollowedItDoesNotHold(): void
    {
        // Given
        $token = $this->issue();

        // When
        try {
            $this->handle(self::request([
                'redirect_uris' => ['https://rp.example/cb#fragment'],
            ]));
        } catch (UnreadableClientMetadataException) {
        }

        // Then
        static::assertTrue($token->isSpent());
        static::assertSame([], $this->store->records);
    }

    /**
     * Decision 0009
     */
    #[Test]
    public function aScopeTheTenantDoesNotOfferRegistersNothing(): void
    {
        // Given
        $this->issue();

        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('which this tenant does not hand out tokens for (decision 0009)');

        // When
        $this->handle(self::request([
            'redirect_uris' => ['https://rp.example/cb'],
            'scope' => 'openid billing.read',
        ]));
    }

    /**
     * RFC 7591 §3.1.1, RFC 7592 §2.2
     */
    #[Test]
    public function aClientRegisteredOnAStatementKeepsWhatItSignedApart(): void
    {
        // Given
        $policies = self::createStub(ClientRegistrationPolicyInterface::class);
        $policies->method('policyFor')->willReturn(Policies::attested([SoftwareStatements::authority()]));

        // When
        $response = $this->handle(new RegistrationRequest([
            'redirect_uris' => ['https://rp.example/cb'],
            'client_name' => 'What the client typed',
            'software_statement' => SoftwareStatements::statement((string) $this->tenant->issuer, Fixtures::now()),
        ]), $policies);

        // Then
        static::assertSame(
            [
                'software_id' => SoftwareStatements::SOFTWARE_ID,
                'software_version' => '2.1.0',
                'client_name' => 'Invoice reader, attested',
            ],
            $response->record->attested,
        );
    }

    #[Test]
    public function aClientRegisteredOnAnInitialAccessTokenKeepsNothingApart(): void
    {
        // Given
        $this->issue();

        // When
        $response = $this->handle(self::request());

        // Then
        static::assertNull($response->record->attested);
    }

    private function issue(): InitialAccessToken
    {
        $token = new InitialAccessToken(
            Uuid::v7(),
            $this->tenant,
            DrawnSecret::digestOf(self::TOKEN),
            'The team that integrates',
            1,
            Fixtures::now(),
            Fixtures::now()->modify('+1 day'),
        );
        $this->tokens->save($token);

        return $token;
    }

    private function handle(RegistrationRequest $request, ?ClientRegistrationPolicyInterface $policies = null): ClientInformationResponse
    {
        $clock = new MockClock(Fixtures::now());

        return new ClientRegistrationHandler(
            $policies ?? RegistrationPolicies::controlled(),
            new RegistrationAuthorizations([
                new InitialAccessTokenAuthorization($this->tokens, $clock),
                new OpenRegistrationAuthorization(),
                new SoftwareStatementAuthorization(
                    new SoftwareStatementVerifier(
                        new JwtLibraryCompactJwtReader(),
                        new JwtLibraryJwtKeyVerifier(Algorithms::all()->manager()),
                        new InMemorySoftwareStatementReplayGuard(),
                        new DateInterval('PT5M'),
                        new DateInterval('PT30S'),
                    ),
                    $clock,
                ),
            ]),
            Registrations::underThePolicy(),
            new ClientIdentifierDrawer(Secrets::drawer(), new RegisteredClients([new InMemoryClientRepository()])),
            Secrets::drawer(),
            $this->store,
            new Endpoints(),
            $clock,
        )->handle($this->tenant, $request);
    }

    /**
     * @param array<string, mixed>|null $members
     */
    private static function request(?array $members = null): RegistrationRequest
    {
        return new RegistrationRequest(
            $members ?? [
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            'Bearer ' . self::TOKEN,
        );
    }
}
