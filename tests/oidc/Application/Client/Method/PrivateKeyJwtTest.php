<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Method;

use function array_map;
use function count;
use DateInterval;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Exception\InvalidClientException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeClientJwksFetcher;
use Beffroi\Oidc\Tests\Fixture\FakeClientLoadBudget;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * OIDC Core §9, RFC 7523
 */
final class PrivateKeyJwtTest extends TestCase
{
    private const string ENDPOINT = 'https://id.acme.example/token';

    private const string BACKCHANNEL_ENDPOINT = 'https://id.acme.example/backchannel_authentication';

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
     * RFC 7523 §3
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
     * FAPI 2.0 Security Profile §5.3.2.1 clause 8
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
     * RFC 7519 §4.1.3
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
     * RFC 7523 §3
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
     * RFC 7523 §4
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
     * RFC 7523 §3
     */
    #[Test]
    public function itRefusesAnAssertionWithoutAnExpiry(): void
    {
        // Given
        $claims = ClientAssertions::claims($this->client->registration->clientId, $this->tenant->issuer->value, $this->context->receivedAt);
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
     * RFC 7523 §3, RFC 7519 §4.1.5
     */
    #[Test]
    #[DataProvider('provideStartsToCome')]
    public function itRefusesAnAssertionBeforeItsNotBefore(int $secondsAhead): void
    {
        // When
        $this->failToAuthenticate($this->assertion([
            'nbf' => $this->context->receivedAt->getTimestamp() + $secondsAhead,
        ]));

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideStartsToCome(): iterable
    {
        yield 'an hour ahead' => [3600];
        yield 'a second beyond the leeway' => [31];
    }

    /**
     * RFC 7519 §2, §4.1.5
     */
    #[Test]
    #[DataProvider('provideStartsThatAreNoNumericDate')]
    public function itRefusesAnAssertionWhoseNotBeforeIsNoNumericDate(mixed $notBefore): void
    {
        // When
        $this->failToAuthenticate($this->assertion([
            'nbf' => $notBefore,
        ]));

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideStartsThatAreNoNumericDate(): iterable
    {
        yield 'a date written as text' => ['2026-09-15T10:00:00+00:00'];
        yield 'a number written as text' => ['1757930400'];
        yield 'a null' => [null];
    }

    /**
     * RFC 7523 §3, RFC 7519 §4.1.5
     */
    #[Test]
    #[DataProvider('provideStartsThatHaveCome')]
    public function itAuthenticatesAClientWhoseAssertionHasStarted(int $secondsAhead): void
    {
        // When
        $authenticated = $this->authenticate($this->assertion([
            'nbf' => $this->context->receivedAt->getTimestamp() + $secondsAhead,
        ]));

        // Then
        static::assertSame($this->client, $authenticated->client);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideStartsThatHaveCome(): iterable
    {
        yield 'a minute ago' => [-60];
        yield 'now' => [0];
        yield 'inside the leeway' => [30];
    }

    /**
     * RFC 7519 §4.1.3, FAPI 2.0 Security Profile §5.3.2.1 clause 8
     */
    #[Test]
    #[DataProvider('provideAudiencesThatAreNeitherAStringNorAListOfThem')]
    public function itRefusesAnAudienceThatIsNeitherAStringNorAListOfThem(mixed $audience): void
    {
        // When
        $this->failToAuthenticate($this->assertion([
            'aud' => $audience,
        ]));

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideAudiencesThatAreNeitherAStringNorAListOfThem(): iterable
    {
        $issuer = Fixtures::tenant()->issuer->value;

        yield 'the issuer beside a number' => [[$issuer, 5]];
        yield 'the issuer beside a boolean and a null' => [[$issuer, true, null]];
        yield 'the issuer inside an object' => [
            [
                'x' => $issuer,
            ],
        ];
    }

    /**
     * RFC 7523 §3
     */
    #[Test]
    public function itRefusesAnAssertionWithoutAnIdentifier(): void
    {
        // Given
        $claims = ClientAssertions::claims($this->client->registration->clientId, $this->tenant->issuer->value, $this->context->receivedAt);
        unset($claims['jti']);

        // When
        $this->failToAuthenticate(ClientAssertions::signedWithKey($claims));

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

    /**
     * RFC 7523 §3
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
     * RFC 7523 §3
     */
    #[Test]
    public function itRefusesAnAssertionThatNamesNoClient(): void
    {
        // Given
        $claims = ClientAssertions::claims($this->client->registration->clientId, $this->tenant->issuer->value, $this->context->receivedAt);
        unset($claims['sub']);

        // When
        $exception = $this->failToAuthenticate(ClientAssertions::signedWithKey($claims));

        // Then
        static::assertInstanceOf(InvalidClientException::class, $exception);
        $refusal = $this->lastRefusal();
        static::assertSame(ClientAuthenticationFailureReason::InvalidAssertion, $refusal->reason);
        static::assertNull($refusal->clientId);
        static::assertNull($refusal->method);
    }

    /**
     * RFC 7523 §3, OIDC Core §9
     */
    #[Test]
    public function theClientIdOfTheBodyNamesTheClientWhenTheAssertionDoesNot(): void
    {
        // Given
        $claims = ClientAssertions::claims($this->client->registration->clientId, $this->tenant->issuer->value, $this->context->receivedAt);
        unset($claims['sub']);

        // When
        $this->authenticateFailing(null, [
            'client_id' => $this->client->registration->clientId,
            ...ClientAssertions::parameters(ClientAssertions::signedWithKey($claims)),
        ]);

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

    /**
     * RFC 6749 §5.2
     */
    #[Test]
    public function theSubOfTheAssertionNamesTheClientWhenTheBodyNamesAnother(): void
    {
        // When
        $exception = $this->authenticateFailing(null, [
            'client_id' => 'basic-client',
            ...ClientAssertions::parameters($this->assertion()),
        ]);

        // Then
        static::assertInstanceOf(InvalidRequestException::class, $exception);
        $this->assertRefused(ClientAuthenticationFailureReason::MismatchedClientId);
    }

    #[Test]
    public function itRefusesAnAssertionSignedByAnotherKey(): void
    {
        // Given
        $assertion = ClientAssertions::signedWithKey(
            ClientAssertions::claims($this->client->registration->clientId, $this->tenant->issuer->value, $this->context->receivedAt),
            [],
            self::strangerKey(),
        );

        // When
        $this->failToAuthenticate($assertion);

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

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

    #[Test]
    public function aClientPresentingASecretInsteadIsRefusedLikeAnyOther(): void
    {
        // When
        $exception = $this->authenticateFailing(null, [
            'client_id' => $this->client->registration->clientId,
            'client_secret' => Clients::SECRET,
        ]);

        // Then
        static::assertInstanceOf(InvalidClientException::class, $exception);
        static::assertSame('Client authentication failed.', $exception->errorDescription);
        $this->assertRefused(ClientAuthenticationFailureReason::UnexpectedMethod, $this->client->registration->clientId, 'client_secret_post');
    }

    /**
     * CIBA Core §7.1
     */
    #[Test]
    public function aClientOfTheBackchannelFlowIsAuthenticatedNamingTheTokenEndpoint(): void
    {
        // Given
        $client = $this->backchannelClient();

        // When
        $authenticated = $this->authenticateBackchannel($client, self::ENDPOINT);

        // Then
        static::assertSame($client, $authenticated->client);
    }

    /**
     * CIBA Core §7.1
     */
    #[Test]
    public function aClientOfTheBackchannelFlowIsAuthenticatedNamingTheBackchannelEndpoint(): void
    {
        // Given
        $client = $this->backchannelClient();

        // When
        $authenticated = $this->authenticateBackchannel($client, self::BACKCHANNEL_ENDPOINT);

        // Then
        static::assertSame($client, $authenticated->client);
    }

    #[Test]
    public function aClientOfTheBackchannelFlowIsRefusedAnAudienceThatNamesTwoOfThem(): void
    {
        // Given
        $client = $this->backchannelClient();

        // When
        $this->failToAuthenticate(
            $this->assertionOf($client, [$this->tenant->issuer->value, self::ENDPOINT]),
            $this->authenticatorServingCiba(),
        );

        // Then
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion, $client->registration->clientId);
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function assertion(array $overrides = []): string
    {
        return ClientAssertions::signedWithKey(ClientAssertions::claims(
            $this->client->registration->clientId,
            $this->tenant->issuer->value,
            $this->context->receivedAt,
            $overrides,
        ));
    }

    /**
     * CIBA Core §7
     */
    private function backchannelClient(): Client
    {
        $client = Clients::withKeys($this->tenant, 'terminal-client', grantTypes: [Grants::ciba()]);
        $this->clients->save($client);

        return $client;
    }

    /**
     * @param string|list<string> $audience
     */
    private function assertionOf(Client $client, string|array $audience): string
    {
        return ClientAssertions::signedWithKey(ClientAssertions::claims(
            $client->registration->clientId,
            $this->tenant->issuer->value,
            $this->context->receivedAt,
            ['aud' => $audience],
        ));
    }

    private function authenticateBackchannel(Client $client, string $audience): AuthenticatedClient
    {
        return $this->authenticatorServingCiba()->authenticate(
            $this->tenant,
            self::BACKCHANNEL_ENDPOINT,
            null,
            ClientAssertions::parameters($this->assertionOf($client, $audience)),
            $this->context,
        );
    }

    private function authenticatorServingCiba(): ClientAuthenticator
    {
        return new ClientAuthenticator(
            $this->clients,
            Methods::all($this->hasher, claims: Methods::assertionValidator(audiences: Methods::acceptedAudiences(Grants::servedWithCiba()))),
            Methods::requestParser(),
            new MockClock('2026-09-15T10:00:00+00:00'),
            $this->events,
            new FakeClientLoadBudget(),
        );
    }

    private function authenticator(): ClientAuthenticator
    {
        return new ClientAuthenticator(
            $this->clients,
            Methods::all($this->hasher),
            Methods::requestParser(),
            new MockClock('2026-09-15T10:00:00+00:00'),
            $this->events,
            new FakeClientLoadBudget(),
        );
    }

    private function authenticatorFetching(FakeClientJwksFetcher $fetcher): ClientAuthenticator
    {
        $keys = Methods::keySetProvider($fetcher, new MockClock('2026-09-15T10:00:00+00:00'), new DateInterval('PT300S'));

        return new ClientAuthenticator(
            $this->clients,
            Methods::all($this->hasher, $keys),
            Methods::requestParser(),
            new MockClock('2026-09-15T10:00:00+00:00'),
            $this->events,
            new FakeClientLoadBudget(),
        );
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
        $last = $this->lastRefusal();
        static::assertSame($reason, $last->reason);
        static::assertSame($clientId ?? $this->client->registration->clientId, $last->clientId);
        static::assertSame($method, $last->method);
    }

    private function lastRefusal(): ClientAuthenticationFailed
    {
        $events = $this->events->of(ClientAuthenticationFailed::class);

        return $events[count($events) - 1];
    }

    private static function strangerKey(): JWK
    {
        return new JWK([
            ...Algorithms::es256()->generateKey()->all(),
            'kid' => ClientAssertions::KEY_ID,
        ]);
    }
}
