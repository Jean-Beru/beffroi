<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client;

use function base64_encode;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\LoadBudgetSpentException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Exception\InvalidClientException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeClientLoadBudget;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\RecordingCompactJwtReader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_starts_with;
use Symfony\Component\Clock\MockClock;
use function urlencode;

final class ClientAuthenticatorTest extends TestCase
{
    private const string CHALLENGE = 'Basic realm="https://id.acme.example"';

    /**
     * The endpoint that received the request; an assertion may name it as its audience (RFC 7523 §3).
     */
    private const string ENDPOINT = 'https://id.acme.example/token';

    private Tenant $tenant;

    private RequestContext $context;

    private FakePasswordHasher $hasher;

    private InMemoryClientRepository $clients;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private FakeClientLoadBudget $budget;

    private ClientAuthenticator $authenticator;

    private Client $basicClient;

    private Client $postClient;

    private Client $publicClient;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->context = Fixtures::context();
        $this->hasher = new FakePasswordHasher();
        $this->clients = new InMemoryClientRepository();
        $this->basicClient = Clients::confidential($this->tenant, $this->hasher->hash(Clients::SECRET), Methods::clientSecretBasic(), 'basic-client');
        $this->postClient = Clients::confidential($this->tenant, $this->hasher->hash(Clients::SECRET), Methods::clientSecretPost(), 'post-client');
        $this->publicClient = Clients::public($this->tenant, 'public-client');
        $this->clients->save($this->basicClient);
        $this->clients->save($this->postClient);
        $this->clients->save($this->publicClient);
        $this->clients->save(Clients::confidential(
            Fixtures::tenant('other', 'https://id.other.example'),
            $this->hasher->hash(Clients::SECRET),
            Methods::clientSecretBasic(),
            'foreign-client',
        ));
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-15T12:00:00+00:00');
        $this->budget = new FakeClientLoadBudget();
        $this->authenticator = new ClientAuthenticator(
            $this->clients,
            Methods::all($this->hasher),
            Methods::requestParser(),
            $this->clock,
            $this->events,
            $this->budget,
        );
    }

    /**
     * RFC 6749 §2.3.1: the identifier and the secret are form-urlencoded before being Basic-encoded, which
     * is what Symfony's ClientSecretBasic sends.
     */
    #[Test]
    public function itAuthenticatesWithClientSecretBasic(): void
    {
        // When
        $client = $this->authenticator->authenticate(
            $this->tenant,
            self::ENDPOINT,
            self::basic('basic-client', Clients::SECRET),
            [
                'grant_type' => 'authorization_code',
            ],
            $this->context,
        );

        // Then
        static::assertSame($this->basicClient, $client->client);
    }

    /**
     * The secret is compared by the hasher, against the client's own hash, exactly once.
     */
    #[Test]
    public function itVerifiesTheSecretAgainstTheHashOfTheClientOnce(): void
    {
        // When
        $this->authenticator->authenticate($this->tenant, self::ENDPOINT, self::basic('basic-client', Clients::SECRET), [], $this->context);

        // Then
        static::assertSame([self::hashOf($this->basicClient)], $this->hasher->verifiedAgainst);
    }

    #[Test]
    public function aSuccessfulAuthenticationAnnouncesNothing(): void
    {
        // When
        $this->authenticator->authenticate($this->tenant, self::ENDPOINT, self::basic('basic-client', Clients::SECRET), [], $this->context);

        // Then
        static::assertSame([], $this->events->events);
    }

    /**
     * Decision 0014: the load budget of a client is counted where its identifier is proven, by tenant
     * and by client.
     */
    #[Test]
    public function anAuthenticatedClientTakesOneOfItsLoadBudget(): void
    {
        // When
        $this->authenticator->authenticate($this->tenant, self::ENDPOINT, self::basic('basic-client', Clients::SECRET), [], $this->context);

        // Then
        static::assertSame([$this->tenant->slug . '|basic-client'], $this->budget->consumed);
    }

    /**
     * Decision 0014: a budget counted on an identifier that was only claimed is emptied by naming
     * somebody else's client, so a client that proves nothing (RFC 6749 §2.1) is counted nowhere here.
     */
    #[Test]
    public function aPublicClientTakesNothingOfTheLoadBudgetOfAClient(): void
    {
        // When
        $this->authenticator->authenticate($this->tenant, self::ENDPOINT, null, ['client_id' => 'public-client'], $this->context);

        // Then
        static::assertSame([], $this->budget->consumed);
    }

    /**
     * Decision 0014: what a refusal costs is bounded by the budget of the origin of the request, the
     * client not being known to be the client until the secret verifies.
     */
    #[Test]
    public function aRefusedClientTakesNothingOfTheLoadBudgetOfAClient(): void
    {
        // When
        try {
            $this->authenticator->authenticate($this->tenant, self::ENDPOINT, self::basic('basic-client', 'not-the-secret'), [], $this->context);
        } catch (InvalidClientException) {
        }

        // Then
        static::assertSame([], $this->budget->consumed);
    }

    /**
     * Decision 0014: the refusal is not an error of the protocol and leaves the authenticator as it was
     * thrown, for the one thing that answers it to turn it into the 429 of RFC 6585 §4.
     */
    #[Test]
    public function aClientWhoseLoadBudgetIsSpentIsRefused(): void
    {
        // Given
        $authenticator = new ClientAuthenticator(
            $this->clients,
            Methods::all($this->hasher),
            Methods::requestParser(),
            $this->clock,
            $this->events,
            new FakeClientLoadBudget(0),
        );

        // Then
        $this->expectException(LoadBudgetSpentException::class);
        $this->expectExceptionMessageIs('The "client" budget is spent; the request is served again in 42 seconds.');

        // When
        $authenticator->authenticate($this->tenant, self::ENDPOINT, self::basic('basic-client', Clients::SECRET), [], $this->context);
    }

    /**
     * RFC 7523 §2.2, issue #246: the assertion a request carries is read once, before any method sees the
     * request. Two of the wired methods take an assertion and the one that authenticates reads it again
     * to verify it and to judge its claims; the reader is asked once all the same.
     */
    #[Test]
    public function theAssertionOfARequestIsReadOnceWhateverReadsItAfterwards(): void
    {
        // Given
        $reader = new RecordingCompactJwtReader();
        $authenticator = new ClientAuthenticator(
            $this->clients,
            Methods::all($this->hasher),
            Methods::requestParser($reader),
            $this->clock,
            $this->events,
            $this->budget,
        );
        $this->clients->save(Clients::withKeys($this->tenant));
        $assertion = ClientAssertions::signedWithKey(
            ClientAssertions::claims('key-client', $this->tenant->issuer->value, $this->context->receivedAt),
        );

        // When
        $authenticator->authenticate($this->tenant, self::ENDPOINT, null, ClientAssertions::parameters($assertion), $this->context);

        // Then
        static::assertSame([$assertion], $reader->read);
    }

    /**
     * RFC 6749 §2.3.1: a colon, a plus sign or a percent sign in the secret survives the encoding.
     */
    #[Test]
    public function itDecodesTheFormEncodedBasicCredentials(): void
    {
        // Given
        $secret = 'a+b%c:d e' . Clients::SECRET;
        $this->clients->save(Clients::confidential($this->tenant, $this->hasher->hash($secret), Methods::clientSecretBasic(), 'odd client'));

        // When
        $client = $this->authenticator->authenticate($this->tenant, self::ENDPOINT, self::basic('odd client', $secret), [], $this->context);

        // Then
        static::assertSame('odd client', $client->client->registration->clientId);
    }

    /**
     * RFC 7235 §2.1: the scheme is case-insensitive, followed by one or more spaces.
     */
    #[Test]
    public function itReadsTheSchemeCaseInsensitively(): void
    {
        // Given
        $header = "BASIC \t  " . base64_encode('basic-client:' . Clients::SECRET);

        // When
        $client = $this->authenticator->authenticate($this->tenant, self::ENDPOINT, $header, [], $this->context);

        // Then
        static::assertSame($this->basicClient, $client->client);
    }

    /**
     * RFC 7617 §2: the first colon separates the identifier from the secret; a client that did not encode a
     * colon in its secret is still understood, because the identifier never contains one.
     */
    #[Test]
    public function onlyTheFirstColonSeparatesTheIdentifierFromTheSecret(): void
    {
        // Given
        $secret = 'with:colons:' . Clients::SECRET;
        $this->clients->save(Clients::confidential($this->tenant, $this->hasher->hash($secret), Methods::clientSecretBasic(), 'colon-client'));

        // When
        $client = $this->authenticator->authenticate($this->tenant, self::ENDPOINT, 'Basic ' . base64_encode('colon-client:' . $secret), [], $this->context);

        // Then
        static::assertSame('colon-client', $client->client->registration->clientId);
    }

    /**
     * Symfony's OidcClient always sends client_id in the body, whatever the authentication method.
     */
    #[Test]
    public function itAcceptsAMatchingClientIdInTheBodyNextToTheHeader(): void
    {
        // When
        $client = $this->authenticator->authenticate(
            $this->tenant,
            self::ENDPOINT,
            self::basic('basic-client', Clients::SECRET),
            [
                'client_id' => 'basic-client',
            ],
            $this->context,
        );

        // Then
        static::assertSame($this->basicClient, $client->client);
    }

    /**
     * RFC 6749 §2.3.1: client_id and client_secret in the request body.
     */
    #[Test]
    public function itAuthenticatesWithClientSecretPost(): void
    {
        // When
        $client = $this->authenticator->authenticate(
            $this->tenant,
            self::ENDPOINT,
            null,
            [
                'client_id' => 'post-client',
                'client_secret' => Clients::SECRET,
            ],
            $this->context,
        );

        // Then
        static::assertSame($this->postClient, $client->client);
        static::assertSame([self::hashOf($this->postClient)], $this->hasher->verifiedAgainst);
    }

    /**
     * RFC 6749 §2.1, §3.2.1: a public client only identifies itself.
     */
    #[Test]
    public function itIdentifiesAPublicClientByItsIdAlone(): void
    {
        // When
        $client = $this->authenticator->authenticate(
            $this->tenant,
            self::ENDPOINT,
            null,
            [
                'client_id' => 'public-client',
            ],
            $this->context,
        );

        // Then
        static::assertSame($this->publicClient, $client->client);
        static::assertSame([], $this->hasher->verifiedAgainst);
    }

    /**
     * RFC 6749 §2.3: more than one authentication method is invalid_request.
     */
    #[Test]
    public function itRefusesAHeaderAndABodySecretTogether(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);

        // When
        $this->authenticator->authenticate(
            $this->tenant,
            self::ENDPOINT,
            self::basic('basic-client', Clients::SECRET),
            [
                'client_id' => 'basic-client',
                'client_secret' => Clients::SECRET,
            ],
            $this->context,
        );
    }

    /**
     * RFC 6749 §2.3: two methods are refused before any lookup.
     */
    #[Test]
    public function twoMethodsAreRefusedBeforeAnyVerification(): void
    {
        // When
        $this->failToAuthenticate(self::basic('basic-client', Clients::SECRET), [
            'client_id' => 'basic-client',
            'client_secret' => Clients::SECRET,
        ]);

        // Then
        static::assertSame([], $this->hasher->verifiedAgainst);
    }

    #[Test]
    public function twoMethodsAreAnnouncedWithTheIdentifierOfTheHeader(): void
    {
        // When
        $this->failToAuthenticate(self::basic('basic-client', Clients::SECRET), [
            'client_id' => 'basic-client',
            'client_secret' => Clients::SECRET,
        ]);

        // Then
        $this->assertFailureAnnounced(ClientAuthenticationFailureReason::MultipleMechanisms, 'basic-client', null);
    }

    #[Test]
    public function itRefusesABodyClientIdThatDiffersFromTheHeader(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);

        // When
        $this->authenticator->authenticate(
            $this->tenant,
            self::ENDPOINT,
            self::basic('basic-client', Clients::SECRET),
            [
                'client_id' => 'post-client',
            ],
            $this->context,
        );
    }

    #[Test]
    public function aMismatchedClientIdIsAnnouncedWithTheIdentifierOfTheHeader(): void
    {
        // When
        $this->failToAuthenticate(self::basic('basic-client', Clients::SECRET), [
            'client_id' => 'post-client',
        ]);

        // Then
        $this->assertFailureAnnounced(ClientAuthenticationFailureReason::MismatchedClientId, 'basic-client', 'client_secret_basic');
    }

    /**
     * RFC 6749 §5.2: an unsupported authentication method is invalid_client; the challenge names the
     * scheme the provider supports.
     */
    #[Test]
    #[DataProvider('provideHeadersThatAreNotBasic')]
    public function itRefusesAnAuthorizationHeaderThatIsNotBasic(string $header): void
    {
        // When
        $exception = $this->failToAuthenticate($header, [
            'client_id' => 'basic-client',
        ]);

        // Then
        static::assertInstanceOf(InvalidClientException::class, $exception);
        static::assertSame(self::CHALLENGE, $exception->challenge);
    }

    #[Test]
    #[DataProvider('provideHeadersThatAreNotBasic')]
    public function anUnsupportedSchemeIsAnnouncedWithoutIdentifier(string $header): void
    {
        // When
        $this->failToAuthenticate($header, [
            'client_id' => 'basic-client',
        ]);

        // Then
        $this->assertFailureAnnounced(ClientAuthenticationFailureReason::UnsupportedScheme, null, null);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideHeadersThatAreNotBasic(): iterable
    {
        $credentials = base64_encode('basic-client:' . Clients::SECRET);

        yield 'Bearer' => ['Bearer ' . Clients::SECRET];
        yield 'Basic without credentials nor space' => ['Basic'];
        yield 'scheme not at the start' => ['x Basic ' . $credentials];
        yield 'something after the credentials' => ['Basic ' . $credentials . ' extra'];
        yield 'a line feed behind the credentials' => ['Basic ' . $credentials . "\n"];
    }

    #[Test]
    #[DataProvider('provideMalformedBasicCredentials')]
    public function itRefusesMalformedBasicCredentials(string $header): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);

        // When
        $this->authenticator->authenticate($this->tenant, self::ENDPOINT, $header, [], $this->context);
    }

    #[Test]
    #[DataProvider('provideMalformedBasicCredentials')]
    public function malformedBasicCredentialsCostNoVerification(string $header): void
    {
        // When
        $this->failToAuthenticate($header, []);

        // Then
        static::assertSame([], $this->hasher->verifiedAgainst);
    }

    #[Test]
    #[DataProvider('provideMalformedBasicCredentials')]
    public function malformedBasicCredentialsAreAnnouncedWithTheMethodUsed(string $header): void
    {
        // When
        $this->failToAuthenticate($header, []);

        // Then
        $this->assertFailureAnnounced(ClientAuthenticationFailureReason::MalformedCredentials, null, 'client_secret_basic');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMalformedBasicCredentials(): iterable
    {
        yield 'nothing after the scheme' => ['Basic '];
        yield 'nothing but spaces after the scheme' => ['Basic    '];
        yield 'not base64' => ['Basic not*base64'];
        yield 'no colon' => ['Basic ' . base64_encode('basic-client')];
        yield 'empty identifier' => ['Basic ' . base64_encode(':' . Clients::SECRET)];
    }

    /**
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('provideNonStringParameters')]
    public function itRefusesNonStringParameters(array $parameters): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);

        // When
        $this->authenticator->authenticate($this->tenant, self::ENDPOINT, null, $parameters, $this->context);
    }

    /**
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('provideNonStringParameters')]
    public function nonStringParametersAreAnnouncedWithoutIdentifier(array $parameters): void
    {
        // When
        $this->failToAuthenticate(null, $parameters);

        // Then
        $this->assertFailureAnnounced(ClientAuthenticationFailureReason::MalformedCredentials, null, null);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideNonStringParameters(): iterable
    {
        yield 'client_id as a list' => [[
            'client_id' => ['basic-client'],
        ]];
        yield 'client_secret as a list' => [[
            'client_id' => 'post-client',
            'client_secret' => [Clients::SECRET],
        ]];
    }

    /**
     * A request whose credentials are not strings is refused before anything is read, and the audit
     * trail keeps no identifier from it: none of what it carries can be trusted, the header included.
     */
    #[Test]
    public function aMalformedBodyNextToAHeaderIsAnnouncedWithoutIdentifier(): void
    {
        // When
        $exception = $this->failToAuthenticate(self::basic('basic-client', Clients::SECRET), [
            'client_id' => ['basic-client'],
        ]);

        // Then
        static::assertInstanceOf(InvalidRequestException::class, $exception);
        $this->assertFailureAnnounced(ClientAuthenticationFailureReason::MalformedCredentials, null, null);
    }

    /**
     * RFC 7523 §2.2, RFC 6749 §5.2 (issue #863): an assertion of another type than the one of the specification is a
     * request no method can read, answered invalid_request with a description the client can read, and never a
     * server error.
     */
    #[Test]
    public function anAssertionOfAnotherTypeIsAnInvalidRequest(): void
    {
        // When
        $exception = $this->failToAuthenticate(null, [
            'client_assertion' => 'an.assertion.here',
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:saml2-bearer',
        ]);

        // Then
        static::assertInstanceOf(InvalidRequestException::class, $exception);
        static::assertSame('invalid_request', $exception->error);
    }

    #[Test]
    public function itRefusesABodySecretWithoutAClientId(): void
    {
        // When
        $exception = $this->failToAuthenticate(null, [
            'client_secret' => Clients::SECRET,
        ]);

        // Then
        static::assertInstanceOf(InvalidRequestException::class, $exception);
        $this->assertFailureAnnounced(ClientAuthenticationFailureReason::MalformedCredentials, null, 'client_secret_post');
    }

    /**
     * RFC 6749 §5.2: "no client authentication included" is invalid_client; no header was used, so no
     * challenge.
     */
    #[Test]
    public function itRefusesARequestWithoutAnyCredentials(): void
    {
        // When
        $exception = $this->failToAuthenticate(null, [
            'grant_type' => 'authorization_code',
        ]);

        // Then
        static::assertInstanceOf(InvalidClientException::class, $exception);
        static::assertNull($exception->challenge);
    }

    #[Test]
    public function aRequestWithoutAnyCredentialsIsAnnouncedAsSuch(): void
    {
        // When
        $this->failToAuthenticate(null, [
            'grant_type' => 'authorization_code',
        ]);

        // Then
        $this->assertFailureAnnounced(ClientAuthenticationFailureReason::NoCredentials, null, null);
    }

    /**
     * An unknown client presenting a secret is invalid_client, with the challenge of the scheme it used,
     * and an error description that does not tell it from a known one.
     */
    #[Test]
    public function anUnknownClientWithABasicSecretIsInvalidClient(): void
    {
        // When
        $exception = $this->failToAuthenticate(self::basic('nobody', Clients::SECRET), []);

        // Then
        static::assertInstanceOf(InvalidClientException::class, $exception);
        static::assertSame(self::CHALLENGE, $exception->challenge);
        static::assertSame('Client authentication failed.', $exception->errorDescription);
    }

    #[Test]
    public function anUnknownClientWithAPostSecretIsInvalidClientWithoutChallenge(): void
    {
        // When
        $exception = $this->failToAuthenticate(null, [
            'client_id' => 'nobody',
            'client_secret' => Clients::SECRET,
        ]);

        // Then
        static::assertInstanceOf(InvalidClientException::class, $exception);
        static::assertNull($exception->challenge);
    }

    /**
     * An unknown client presenting a secret costs a verification against a decoy, the same decoy for the
     * life of the authenticator, so that the time taken does not tell it from a known one.
     */
    #[Test]
    public function anUnknownClientCostsAVerificationAgainstTheSameDecoyEveryTime(): void
    {
        // When
        $this->failToAuthenticate(self::basic('nobody', Clients::SECRET), []);
        $this->failToAuthenticate(null, [
            'client_id' => 'nobody',
            'client_secret' => Clients::SECRET,
        ]);

        // Then
        static::assertCount(2, $this->hasher->verifiedAgainst);
        static::assertSame($this->hasher->verifiedAgainst[0], $this->hasher->verifiedAgainst[1]);
        static::assertTrue(str_starts_with($this->hasher->verifiedAgainst[0], 'fake:'));
        static::assertNotSame(self::hashOf($this->basicClient), $this->hasher->verifiedAgainst[0]);
    }

    #[Test]
    public function anUnknownClientIsAnnouncedWithTheIdentifierAndTheMethodItUsed(): void
    {
        // When
        $this->failToAuthenticate(null, [
            'client_id' => 'nobody',
            'client_secret' => Clients::SECRET,
        ]);

        // Then
        $this->assertFailureAnnounced(ClientAuthenticationFailureReason::UnknownClient, 'nobody', 'client_secret_post');
    }

    #[Test]
    public function anUnknownPublicClientIsInvalidClient(): void
    {
        // When
        $exception = $this->failToAuthenticate(null, [
            'client_id' => 'nobody',
        ]);

        // Then
        static::assertInstanceOf(InvalidClientException::class, $exception);
        $this->assertFailureAnnounced(ClientAuthenticationFailureReason::UnknownClient, 'nobody', 'none');
    }

    #[Test]
    public function anUnknownPublicClientCostsNothing(): void
    {
        // When
        $this->failToAuthenticate(null, [
            'client_id' => 'nobody',
        ]);

        // Then
        static::assertSame([], $this->hasher->verifiedAgainst);
    }

    /**
     * Clients are scoped by tenant: the same identifier in another tenant is unknown here.
     */
    #[Test]
    public function aClientOfAnotherTenantIsUnknown(): void
    {
        // When
        $exception = $this->failToAuthenticate(self::basic('foreign-client', Clients::SECRET), []);

        // Then
        static::assertInstanceOf(InvalidClientException::class, $exception);
        $this->assertFailureAnnounced(ClientAuthenticationFailureReason::UnknownClient, 'foreign-client', 'client_secret_basic');
    }

    /**
     * RFC 6749 §2.3: a method other than the registered one is refused, with the challenge of the scheme used.
     *
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('provideUnexpectedMethods')]
    public function itRefusesAMethodOtherThanTheRegisteredOne(?string $header, array $parameters, string $clientId, string $used, bool $secretPresented): void
    {
        // When
        $exception = $this->failToAuthenticate($header, $parameters);

        // Then
        static::assertInstanceOf(InvalidClientException::class, $exception);
        static::assertSame($header === null ? null : self::CHALLENGE, $exception->challenge);
    }

    /**
     * RFC 6749 §2.3: a method other than the registered one costs the same as a wrong secret, against a
     * decoy, never against the hash of the client.
     *
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('provideUnexpectedMethods')]
    public function anUnexpectedMethodCostsAVerificationAgainstADecoyWhenASecretIsPresented(
        ?string $header,
        array $parameters,
        string $clientId,
        string $used,
        bool $secretPresented,
    ): void {
        // When
        $this->failToAuthenticate($header, $parameters);

        // Then
        static::assertCount($secretPresented ? 1 : 0, $this->hasher->verifiedAgainst);
        if ($secretPresented) {
            static::assertTrue(str_starts_with($this->hasher->verifiedAgainst[0], 'fake:'));
            static::assertNotSame(self::hashOf($this->basicClient), $this->hasher->verifiedAgainst[0]);
            static::assertNotSame(self::hashOf($this->postClient), $this->hasher->verifiedAgainst[0]);
        }
    }

    /**
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('provideUnexpectedMethods')]
    public function anUnexpectedMethodIsAnnouncedWithTheMethodUsed(
        ?string $header,
        array $parameters,
        string $clientId,
        string $used,
        bool $secretPresented,
    ): void {
        // When
        $this->failToAuthenticate($header, $parameters);

        // Then
        $this->assertFailureAnnounced(ClientAuthenticationFailureReason::UnexpectedMethod, $clientId, $used);
    }

    /**
     * @return iterable<string, array{string|null, array<string, mixed>, string, string, bool}>
     */
    public static function provideUnexpectedMethods(): iterable
    {
        yield 'registered basic, used post' => [
            null,
            [
                'client_id' => 'basic-client',
                'client_secret' => Clients::SECRET,
            ],
            'basic-client',
            'client_secret_post',
            true,
        ];
        yield 'registered basic, used none' => [
            null,
            [
                'client_id' => 'basic-client',
            ],
            'basic-client',
            'none',
            false,
        ];
        yield 'registered post, used basic' => [self::basic('post-client', Clients::SECRET), [], 'post-client', 'client_secret_basic', true];
        yield 'registered none, used basic' => [self::basic('public-client', Clients::SECRET), [], 'public-client', 'client_secret_basic', true];
        yield 'registered none, used post' => [
            null,
            [
                'client_id' => 'public-client',
                'client_secret' => Clients::SECRET,
            ],
            'public-client',
            'client_secret_post',
            true,
        ];
    }

    /**
     * A wrong secret is invalid_client, with the challenge and a description that does not say why.
     */
    #[Test]
    public function aWrongSecretIsInvalidClient(): void
    {
        // When
        $exception = $this->failToAuthenticate(self::basic('basic-client', 'wrong ' . Clients::SECRET), []);

        // Then
        static::assertInstanceOf(InvalidClientException::class, $exception);
        static::assertSame(self::CHALLENGE, $exception->challenge);
        static::assertSame('Client authentication failed.', $exception->errorDescription);
    }

    /**
     * The secret is compared by the hasher, against the client's own hash, exactly once.
     */
    #[Test]
    public function aWrongSecretIsVerifiedAgainstTheHashOfTheClientOnce(): void
    {
        // When
        $this->failToAuthenticate(self::basic('basic-client', 'wrong ' . Clients::SECRET), []);

        // Then
        static::assertSame([self::hashOf($this->basicClient)], $this->hasher->verifiedAgainst);
    }

    #[Test]
    public function aWrongSecretIsAnnouncedWithTheClientAndTheMethod(): void
    {
        // When
        $this->failToAuthenticate(self::basic('basic-client', 'wrong ' . Clients::SECRET), []);

        // Then
        $this->assertFailureAnnounced(ClientAuthenticationFailureReason::InvalidSecret, 'basic-client', 'client_secret_basic');
    }

    #[Test]
    public function aWrongPostSecretIsInvalidClientWithoutAChallenge(): void
    {
        // When
        $exception = $this->failToAuthenticate(null, [
            'client_id' => 'post-client',
            'client_secret' => '',
        ]);

        // Then
        static::assertInstanceOf(InvalidClientException::class, $exception);
        static::assertNull($exception->challenge);
        $this->assertFailureAnnounced(ClientAuthenticationFailureReason::InvalidSecret, 'post-client', 'client_secret_post');
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private function failToAuthenticate(?string $header, array $parameters): OAuth2Exception
    {
        try {
            $this->authenticator->authenticate($this->tenant, self::ENDPOINT, $header, $parameters, $this->context);
        } catch (OAuth2Exception $exception) {
            return $exception;
        }
        static::fail('The client should not have been authenticated.');
    }

    /**
     * RFC 8705 §3.4: a client that registered certificate-bound access tokens is bound to the
     * certificate of its connection whichever way it authenticated, which is what FAPI 1.0 Advanced
     * Final §5.2.2 asks of a client of a profile that binds and authenticates with an assertion.
     */
    #[Test]
    public function aClientRegisteredForCertificateBoundTokensIsBoundToTheCertificateItPresented(): void
    {
        // Given
        $this->clients->save(Clients::boundToItsCertificate($this->tenant));

        // When
        $authenticated = $this->authenticateWithAnAssertion('bound-terminal', Certificates::client());

        // Then
        static::assertEquals(CertificateConfirmation::ofCertificate(Certificates::client()), $authenticated->confirmation);
    }

    /**
     * RFC 8705 §3: a client reaching the host whose listener asks for a certificate presents one
     * because it was asked, and a client that registered no binding is not bound to it: binding a
     * client that never asked for it would break the resource server it calls.
     */
    #[Test]
    public function aClientRegisteredForNoBindingIsNotBoundToTheCertificateItPresented(): void
    {
        // Given
        $this->clients->save(Clients::withKeys($this->tenant));

        // When
        $authenticated = $this->authenticateWithAnAssertion('key-client', Certificates::client());

        // Then
        static::assertNull($authenticated->confirmation);
    }

    /**
     * OIDC Core §9: the client signs an assertion with the key it published, and presents whatever the
     * handshake gave the provider beside it.
     */
    private function authenticateWithAnAssertion(string $clientId, ClientCertificate $certificate): AuthenticatedClient
    {
        $assertion = ClientAssertions::signedWithKey(
            ClientAssertions::claims($clientId, $this->tenant->issuer->value, $this->context->receivedAt),
        );

        return $this->authenticator->authenticate(
            $this->tenant,
            self::ENDPOINT,
            null,
            ClientAssertions::parameters($assertion),
            $this->context,
            $certificate,
        );
    }

    private function assertFailureAnnounced(ClientAuthenticationFailureReason $reason, ?string $clientId, ?string $method): void
    {
        $events = $this->events->of(ClientAuthenticationFailed::class);
        static::assertCount(1, $events);
        static::assertSame($reason, $events[0]->reason);
        static::assertSame($clientId, $events[0]->clientId);
        static::assertSame($method, $events[0]->method);
        static::assertSame($this->tenant, $events[0]->tenant);
        static::assertSame($this->context, $events[0]->context);
        static::assertEquals($this->clock->now(), $events[0]->occurredAt);
    }

    private static function hashOf(Client $client): string
    {
        $secret = $client->secret;
        static::assertInstanceOf(HashedClientSecret::class, $secret);

        return $secret->hash->encoded;
    }

    private static function basic(string $clientId, string $secret): string
    {
        return 'Basic ' . base64_encode(urlencode($clientId) . ':' . urlencode($secret));
    }
}
