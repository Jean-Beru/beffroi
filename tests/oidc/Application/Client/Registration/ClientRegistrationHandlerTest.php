<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client\Registration;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Client\ClientIdentifierDrawer;
use Heidi\Oidc\Application\Client\RegisteredClients;
use Heidi\Oidc\Application\Client\Registration\ClientRegistrationHandler;
use Heidi\Oidc\Application\Client\Registration\InitialAccessTokenAuthorization;
use Heidi\Oidc\Application\Client\Registration\RegistrationAuthorizations;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientStore;
use Heidi\Oidc\Bridge\InMemory\InMemoryInitialAccessTokenRepository;
use Heidi\Oidc\Domain\Client\HashedClientSecret;
use Heidi\Oidc\Domain\Client\Registration\ClientInformationResponse;
use Heidi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Heidi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Heidi\Oidc\Domain\Client\SharedClientSecret;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\ClientRegistrationNotOfferedException;
use Heidi\Oidc\Exception\InvalidClientMetadataException;
use Heidi\Oidc\Exception\UnauthorizedRegistrationException;
use Heidi\Oidc\Exception\UnreadableClientMetadataException;
use Heidi\Oidc\Port\ClientRegistrationPolicyInterface;
use Heidi\Oidc\Tests\Fixture\Endpoints;
use Heidi\Oidc\Tests\Fixture\RegistrationPolicies;
use Heidi\Oidc\Tests\Fixture\Registrations;
use Heidi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §3.1, decision 0009: a client this provider has never seen asks to exist, and leaves with an
 * identifier, the metadata the provider registered and the secret the method it registered needs.
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
     * Decision 0009: closed is the default, and a closed tenant has no endpoint at all rather than one
     * that reads a request and refuses it. Nothing of the request is read for it.
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
     * RFC 7591 §3.2.1: the provider assigns a secret exactly when the method the client registered
     * proves one, and answers it once.
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

    /**
     * A method that proves no shared secret gets none: the registration says so, and the row holds none.
     */
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
     * OIDC Core §9: "client_secret_jwt" computes a MAC with the secret, so the row keeps it whole rather
     * than a digest of it. Which of the two shapes is kept is the registered method's business.
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
     * Decision 0017: the exemption is written on the registration at the moment the policy creates it,
     * and the row keeps it beside what the client sent, never among it.
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
     * Decision 0017, RFC 9700 §2.1.1: a public client is never exempted, whatever the policy carries,
     * and its registration is not refused for that; it asked for nothing.
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

    /**
     * The row keeps what the client sent, as it sent it: a member this provider learns to read tomorrow
     * is read from the rows that already carry it.
     */
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
     * RFC 7591 §1.2: a token worth one registration registers one, and what it was worth is spent in the
     * request it authorised, whether the registration that followed it was written or refused on its
     * metadata.
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
     * Decision 0009: a client that registers itself is held to what the tenant hands out tokens for, and
     * nothing is written for a registration that is not.
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
            new RegistrationAuthorizations([new InitialAccessTokenAuthorization($this->tokens, $clock)]),
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
