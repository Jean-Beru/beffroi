<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client\Method;

use function array_map;
use function count;
use DateInterval;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Client\AuthenticatedClient;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Exception\ClientKeysUnavailableException;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Tests\Fixture\ClientAssertions;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeClientJwksFetcher;
use Heidi\Oidc\Tests\Fixture\Methods;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * "private_key_jwt" (OIDC Core §9, RFC 7523): the client signs a JWT with a key of its own and the
 * provider verifies it against the keys the client publishes.
 */
final class PrivateKeyJwtTest extends TestCase
{
    private const string ENDPOINT = 'https://id.acme.example/token';

    private const string JWKS_URI = 'https://key.example/jwks';

    private Tenant $tenant;

    private RequestContext $context;

    private InMemoryClientRepository $clients;

    private RecordingEventDispatcher $events;

    private FakePasswordHasher $hasher;

    private Client $client;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->context = Fixtures::context();
        $this->hasher = new FakePasswordHasher();
        $this->clients = new InMemoryClientRepository();
        $this->events = new RecordingEventDispatcher();
        $this->client = Clients::withKeys($this->tenant);
        $this->clients->save($this->client);
        $this->clients->save(Clients::confidential($this->tenant, $this->hasher->hash(Clients::SECRET), Methods::clientSecretBasic(), 'basic-client'));
    }

    /**
     * RFC 7523 §3: "iss" and "sub" name the client, "aud" names the issuer of the provider, "exp", "iat" and "jti" are
     * all there, and the signature verifies against a key the client publishes.
     */
    #[Test]
    public function itAuthenticatesAClientThatSignsWithItsOwnKey(): void
    {
        // When
        $client = $this->authenticate($this->assertion());

        // Then
        static::assertSame($this->client, $client->client);
    }

    #[Test]
    public function aSuccessfulAuthenticationAnnouncesNothing(): void
    {
        // When
        $this->authenticate($this->assertion());

        // Then
        static::assertSame([], $this->events->events);
    }

    /**
     * FAPI 2.0 Security Profile §5.2.2: the endpoint the request was sent to is not an audience, although
     * OIDC Core §9 names it, because an assertion made for one endpoint would then be an assertion for
     * every other one of the same provider.
     */
    #[Test]
    public function itRefusesTheEndpointAsTheAudience(): void
    {
        // When
        $this->failToAuthenticate($this->assertion([
            'aud' => self::ENDPOINT,
        ]));

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

    /**
     * RFC 7519 §4.1.3 lets "aud" be a list; one that names the issuer among other audiences is an
     * assertion made for more than this provider, and it is refused whole.
     */
    #[Test]
    public function itRefusesAnAudienceThatNamesMoreThanTheIssuer(): void
    {
        // When
        $this->failToAuthenticate($this->assertion([
            'aud' => [$this->tenant->issuer->value, self::ENDPOINT],
        ]));

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

    /**
     * RFC 7523 §3: an audience that is not this provider's is not taken.
     */
    #[Test]
    public function itRefusesAnAudienceOfAnotherProvider(): void
    {
        // When
        $this->failToAuthenticate($this->assertion([
            'aud' => 'https://id.other.example/token',
        ]));

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

    /**
     * RFC 7523 §4: an assertion authenticates once.
     */
    #[Test]
    public function itRefusesAnAssertionReplayedInsideItsValidity(): void
    {
        // Given
        $authenticator = $this->authenticator();
        $assertion = $this->assertion();
        $authenticator->authenticate($this->tenant, self::ENDPOINT, null, ClientAssertions::parameters($assertion), $this->context);

        // When
        $this->failToAuthenticate($assertion, $authenticator);

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::ReplayedAssertion);
    }

    /**
     * RFC 7523 §3: "exp" is required.
     */
    #[Test]
    public function itRefusesAnAssertionWithoutAnExpiry(): void
    {
        // Given
        $claims = ClientAssertions::claims($this->client->clientId, $this->tenant->issuer->value, $this->context->receivedAt);
        unset($claims['exp']);

        // When
        $this->failToAuthenticate(ClientAssertions::signedWithKey($claims));

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

    #[Test]
    public function itRefusesAnExpiredAssertion(): void
    {
        // When
        $this->failToAuthenticate($this->assertion([
            'exp' => $this->context->receivedAt->getTimestamp() - 60,
        ]));

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

    /**
     * An assertion is minted for one request: an "exp" a year away is a bearer token nobody watches.
     */
    #[Test]
    public function itRefusesAnExpiryBeyondTheLifetimeItAccepts(): void
    {
        // When
        $this->failToAuthenticate($this->assertion([
            'exp' => $this->context->receivedAt->getTimestamp() + 86400,
        ]));

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

    /**
     * RFC 7523 §3: "jti" is required, because it is what makes the assertion single-use.
     */
    #[Test]
    public function itRefusesAnAssertionWithoutAnIdentifier(): void
    {
        // Given
        $claims = ClientAssertions::claims($this->client->clientId, $this->tenant->issuer->value, $this->context->receivedAt);
        unset($claims['jti']);

        // When
        $this->failToAuthenticate(ClientAssertions::signedWithKey($claims));

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

    /**
     * RFC 7523 §3: an assertion whose "iss" names another client is not this client's.
     */
    #[Test]
    public function itRefusesAnAssertionIssuedByAnotherName(): void
    {
        // When
        $this->failToAuthenticate($this->assertion([
            'iss' => 'somebody-else',
        ]));

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

    /**
     * The signature is verified against the keys of the client and against nothing else.
     */
    #[Test]
    public function itRefusesAnAssertionSignedByAnotherKey(): void
    {
        // Given
        $assertion = ClientAssertions::signedWithKey(
            ClientAssertions::claims($this->client->clientId, $this->tenant->issuer->value, $this->context->receivedAt),
            [],
            self::strangerKey(),
        );

        // When
        $this->failToAuthenticate($assertion);

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

    /**
     * A client that publishes its keys behind a "jwks_uri" is read back over HTTPS and authenticated
     * against what it published there.
     */
    #[Test]
    public function itAuthenticatesAClientThatPublishesItsKeysBehindAJwksUri(): void
    {
        // Given
        $fetcher = new FakeClientJwksFetcher([ClientAssertions::publishedKeys()]);
        $authenticator = $this->authenticatorFetching($fetcher);
        $client = Clients::withKeys($this->tenant, 'remote-client', jwksUri: new ClientUri(self::JWKS_URI));
        $this->clients->save($client);

        // When
        $authenticated = $authenticator->authenticate(
            $this->tenant,
            self::ENDPOINT,
            null,
            ClientAssertions::parameters($this->assertion([
                'iss' => 'remote-client',
                'sub' => 'remote-client',
            ])),
            $this->context,
        );

        // Then
        static::assertSame($client, $authenticated->client);
        static::assertSame([self::JWKS_URI], array_map(static fn (ClientUri $uri): string => $uri->value, $fetcher->fetched));
    }

    /**
     * A "jwks_uri" that answers an error, answers too slowly or redirects fails the authentication and
     * touches nothing else.
     */
    #[Test]
    public function aJwksUriThatCannotBeReadFailsTheAuthentication(): void
    {
        // Given
        $fetcher = new FakeClientJwksFetcher([ClientAssertions::publishedKeys()]);
        $fetcher->failure = new ClientKeysUnavailableException('https://key.example/jwks answered 500.');
        $authenticator = $this->authenticatorFetching($fetcher);
        $this->clients->save(Clients::withKeys($this->tenant, 'remote-client', jwksUri: new ClientUri(self::JWKS_URI)));

        // When
        $exception = $this->failToAuthenticate($this->assertion([
            'iss' => 'remote-client',
            'sub' => 'remote-client',
        ]), $authenticator);

        // Then
        static::assertInstanceOf(InvalidClientException::class, $exception);
        $this->assertRefused(ClientAuthenticationFailureReason::UnreadableClientKeys, 'remote-client');
    }

    /**
     * A client registered for this method and presenting a secret is refused as an unknown client is,
     * with the same message.
     */
    #[Test]
    public function aClientPresentingASecretInsteadIsRefusedLikeAnyOther(): void
    {
        // When
        $exception = $this->authenticateFailing(null, [
            'client_id' => $this->client->clientId,
            'client_secret' => Clients::SECRET,
        ]);

        // Then
        static::assertInstanceOf(InvalidClientException::class, $exception);
        static::assertSame('Client authentication failed.', $exception->errorDescription);
        $this->assertRefused(ClientAuthenticationFailureReason::UnexpectedMethod, $this->client->clientId, 'client_secret_post');
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function assertion(array $overrides = []): string
    {
        return ClientAssertions::signedWithKey(ClientAssertions::claims(
            $this->client->clientId,
            $this->tenant->issuer->value,
            $this->context->receivedAt,
            $overrides,
        ));
    }

    private function authenticator(): ClientAuthenticator
    {
        return new ClientAuthenticator($this->clients, Methods::all($this->hasher), new MockClock('2026-09-15T10:00:00+00:00'), $this->events);
    }

    private function authenticatorFetching(FakeClientJwksFetcher $fetcher): ClientAuthenticator
    {
        $keys = Methods::keySetProvider($fetcher, new MockClock('2026-09-15T10:00:00+00:00'), new DateInterval('PT300S'));

        return new ClientAuthenticator($this->clients, Methods::all($this->hasher, $keys), new MockClock('2026-09-15T10:00:00+00:00'), $this->events);
    }

    private function authenticate(string $assertion): AuthenticatedClient
    {
        return $this->authenticator()->authenticate($this->tenant, self::ENDPOINT, null, ClientAssertions::parameters($assertion), $this->context);
    }

    private function failToAuthenticate(string $assertion, ?ClientAuthenticator $authenticator = null): OAuth2Exception
    {
        $authenticator ??= $this->authenticator();

        try {
            $authenticator->authenticate($this->tenant, self::ENDPOINT, null, ClientAssertions::parameters($assertion), $this->context);
        } catch (OAuth2Exception $exception) {
            return $exception;
        }
        static::fail('The client should not have been authenticated.');
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private function authenticateFailing(?string $header, array $parameters): OAuth2Exception
    {
        try {
            $this->authenticator()->authenticate($this->tenant, self::ENDPOINT, $header, $parameters, $this->context);
        } catch (OAuth2Exception $exception) {
            return $exception;
        }
        static::fail('The client should not have been authenticated.');
    }

    private function assertRefused(ClientAuthenticationFailureReason $reason, ?string $clientId = null, string $method = 'private_key_jwt'): void
    {
        $events = $this->events->of(ClientAuthenticationFailed::class);
        $last = $events[count($events) - 1];
        static::assertSame($reason, $last->reason);
        static::assertSame($clientId ?? $this->client->clientId, $last->clientId);
        static::assertSame($method, $last->method);
    }

    /**
     * A key of somebody else, with the "kid" the client's assertions name, so that the signature and not
     * the lookup is what fails.
     */
    private static function strangerKey(): JWK
    {
        return new JWK([
            ...Algorithms::es256()->generateKey()->all(),
            'kid' => ClientAssertions::KEY_ID,
        ]);
    }
}
