<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Authorization;

use function array_map;
use DateInterval;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Authorization\RequestObjectResolver;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Domain\Client\RequestObject\OneRegisteredAlgorithm;
use Heidi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Heidi\Oidc\Exception\ClientKeysUnavailableException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Exception\RequestObjectUnavailableException;
use Heidi\Oidc\Tests\Fixture\ClientAssertions;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeClientJwksFetcher;
use Heidi\Oidc\Tests\Fixture\FakeRequestObjectFetcher;
use Heidi\Oidc\Tests\Fixture\Methods;
use Heidi\Oidc\Tests\Fixture\RequestObjects;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class RequestObjectResolverTest extends TestCase
{
    private const string PUBLISHED = 'https://jar.example/request.jwt';

    private Tenant $tenant;

    private MockClock $clock;

    private InMemoryClientRepository $clients;

    private RequestObjectResolver $resolver;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clock = new MockClock('2026-09-22T12:00:00+00:00');
        $this->clients = new InMemoryClientRepository();
        $this->clients->save(Clients::sendingRequestObjects($this->tenant));
        $this->resolver = RequestObjects::resolver($this->clients, $this->clock);
    }

    /**
     * A request that carries no object is a request of parameters, which the endpoint reads as it
     * received it.
     */
    #[Test]
    public function aRequestWithoutAnObjectIsLeftAlone(): void
    {
        // When
        $parameters = $this->resolver->resolve($this->tenant, [
            'client_id' => 'jar-client',
            'scope' => 'openid',
        ]);

        // Then
        static::assertNull($parameters);
    }

    /**
     * OIDC Core §6.1: the parameters of the object are the request; a parameter of the query the object
     * does not carry is not part of it.
     */
    #[Test]
    public function theParametersOfTheObjectAreTheRequestAndTheQueryIsDropped(): void
    {
        // Given
        $object = RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now(), [
            'response_type' => 'code',
            'redirect_uri' => 'https://jar.example/callback',
            'scope' => 'openid profile',
        ]));

        // When
        $parameters = $this->resolver->resolve($this->tenant, [
            'client_id' => 'jar-client',
            'request' => $object,
            'scope' => 'openid email',
            'state' => 'only-in-the-query',
        ]);

        // Then
        static::assertSame(
            [
                'client_id' => 'jar-client',
                'response_type' => 'code',
                'redirect_uri' => 'https://jar.example/callback',
                'scope' => 'openid profile',
            ],
            $parameters,
        );
    }

    /**
     * RFC 9126 §2: at an endpoint that authenticated its client, the object is read against that client
     * and the request needs to name nobody: what proved the client is stronger than what it wrote.
     */
    #[Test]
    public function theObjectOfAnAuthenticatedClientIsReadAgainstThatClient(): void
    {
        // Given
        $client = $this->clients->findByClientId($this->tenant, 'jar-client') ?? static::fail('The client should have been found.');
        $object = RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now(), [
            'scope' => 'openid profile',
        ]));

        // When
        $parameters = $this->resolver->resolve(
            $this->tenant,
            [
                'request' => $object,
            ],
            $client,
        );

        // Then
        static::assertSame(
            [
                'client_id' => 'jar-client',
                'scope' => 'openid profile',
            ],
            $parameters,
        );
    }

    /**
     * OIDC Core §6: the two ways in are two, and never both at once.
     */
    #[Test]
    public function anObjectSentByValueAndByReferenceAtOnceIsRefused(): void
    {
        // When / Then
        $this->refuses(
            [
                'client_id' => 'jar-client',
                'request' => RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now())),
                'request_uri' => self::PUBLISHED,
            ],
            'invalid_request',
            'The request and request_uri parameters are never sent together (OIDC Core section 6).',
        );
    }

    /**
     * RFC 9101 §5: the provider has to know whose keys verify the object before it reads any of it, and
     * the "client_id" of the request is what tells it.
     */
    #[Test]
    public function anObjectOfNoNamedClientIsRefused(): void
    {
        // When / Then
        $this->refuses(
            [
                'request' => RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now())),
            ],
            'invalid_request',
            'The client_id parameter is missing.',
        );
    }

    #[Test]
    public function anObjectOfAnUnknownClientIsRefused(): void
    {
        // When / Then
        $this->refuses(
            [
                'client_id' => 'nobody',
                'request' => RequestObjects::signed(RequestObjects::claims('nobody', $this->tenant->issuer->value, $this->clock->now())),
            ],
            'invalid_request',
            'The client is unknown.',
        );
    }

    #[Test]
    public function somethingThatIsNotAJwtIsRefused(): void
    {
        // When / Then
        $this->refuses(
            [
                'client_id' => 'jar-client',
                'request' => 'not-a-jwt',
            ],
            'invalid_request_object',
            'The request object is not a readable JWT (RFC 9101 section 4).',
        );
    }

    /**
     * RFC 9101 §6.2: the key is one the client publishes, and an object signed with another key verifies
     * against none of them.
     */
    #[Test]
    public function anObjectSignedWithAKeyTheClientDoesNotPublishIsRefused(): void
    {
        // Given
        $other = new JWK([
            ...Algorithms::es256()->generateKey()->all(),
            'kid' => ClientAssertions::KEY_ID,
        ]);
        $object = RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now()), [], $other);

        // When / Then
        $this->refuses(
            [
                'client_id' => 'jar-client',
                'request' => $object,
            ],
            'invalid_request_object',
            'The signature of the request object verifies against no key the client publishes.',
        );
    }

    /**
     * OIDC Registration §2: the algorithm is the one the client registered, and no other the provider
     * would take for somebody else.
     */
    #[Test]
    public function anObjectSignedWithAnotherAlgorithmThanTheRegisteredOneIsRefused(): void
    {
        // Given
        $this->clients->save(Clients::sendingRequestObjects($this->tenant, new OneRegisteredAlgorithm(Algorithms::ps256()), clientId: 'ps256-client'));
        $object = RequestObjects::signed(RequestObjects::claims('ps256-client', $this->tenant->issuer->value, $this->clock->now()));

        // When / Then
        $this->refuses(
            [
                'client_id' => 'ps256-client',
                'request' => $object,
            ],
            'invalid_request_object',
            'The request object is not signed with the algorithm the client registered in request_object_signing_alg (OIDC Registration section 2).',
        );
    }

    /**
     * Decision 0006: an unsigned object is read from the client that registered it, and from no other.
     */
    #[Test]
    public function anUnsignedObjectFromAClientThatRegisteredNothingIsRefused(): void
    {
        // Given
        $object = RequestObjects::unsigned(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now()));

        // When / Then
        $this->refuses(
            [
                'client_id' => 'jar-client',
                'request' => $object,
            ],
            'invalid_request_object',
            'The request object is not signed with the algorithm the client registered in request_object_signing_alg (OIDC Registration section 2).',
        );
    }

    /**
     * OIDC Registration §2, the named exception of decision 0006: the object of a client that registered
     * "none" is read, and what it says of the answer is what the answer uses (issue #142).
     */
    #[Test]
    public function anUnsignedObjectFromTheClientThatRegisteredItIsRead(): void
    {
        // Given
        $this->clients->save(Clients::sendingRequestObjects($this->tenant, new UnsignedRequestObjects(), clientId: 'unsigned-client'));
        $object = RequestObjects::unsigned(RequestObjects::claims('unsigned-client', $this->tenant->issuer->value, $this->clock->now(), [
            'response_type' => 'code',
            'redirect_uri' => 'https://jar.example/callback',
            'scope' => 'openid',
            'response_mode' => 'form_post',
        ]));

        // When
        $parameters = $this->resolver->resolve($this->tenant, [
            'client_id' => 'unsigned-client',
            'request' => $object,
        ]);

        // Then
        static::assertSame('form_post', $parameters['response_mode'] ?? null);
        static::assertSame('unsigned-client', $parameters['client_id'] ?? null);
    }

    /**
     * OIDC Discovery §3 "require_request_uri_registration": a URL the client did not register is refused
     * before any request leaves the process.
     */
    #[Test]
    public function anUnregisteredReferenceIsRefusedWithoutARequestLeavingTheProcess(): void
    {
        // Given
        $fetcher = new FakeRequestObjectFetcher();
        $resolver = RequestObjects::resolver($this->clients, $this->clock, $fetcher);

        // When
        try {
            $resolver->resolve($this->tenant, [
                'client_id' => 'jar-client',
                'request_uri' => self::PUBLISHED,
            ]);
            static::fail('An unregistered request_uri should have been refused.');
        } catch (OAuth2Exception $exception) {
            // Then
            static::assertSame('invalid_request_uri', $exception->error);
            static::assertSame([], $fetcher->fetched);
        }
    }

    /**
     * OIDC Core §6.2: the object behind a registered URL is read back and read.
     */
    #[Test]
    public function theObjectBehindARegisteredReferenceIsReadBack(): void
    {
        // Given
        $this->clients->save(Clients::sendingRequestObjects($this->tenant, requestUris: [new ClientUri(self::PUBLISHED)], clientId: 'reference-client'));
        $object = RequestObjects::signed(RequestObjects::claims('reference-client', $this->tenant->issuer->value, $this->clock->now(), [
            'scope' => 'openid profile',
        ]));
        $fetcher = new FakeRequestObjectFetcher($object);
        $resolver = RequestObjects::resolver($this->clients, $this->clock, $fetcher);

        // When
        $parameters = $resolver->resolve($this->tenant, [
            'client_id' => 'reference-client',
            'request_uri' => self::PUBLISHED,
        ]);

        // Then
        static::assertSame('openid profile', $parameters['scope'] ?? null);
        static::assertSame([self::PUBLISHED], array_map(static fn (ClientUri $uri): string => $uri->value, $fetcher->fetched));
    }

    /**
     * Decision 0006: a client that answers an error, too slowly, too much, or a redirection leaves the
     * request refused and the provider untouched.
     */
    #[Test]
    public function aReferenceThatCannotBeReadBackIsRefused(): void
    {
        // Given
        $this->clients->save(Clients::sendingRequestObjects($this->tenant, requestUris: [new ClientUri(self::PUBLISHED)], clientId: 'reference-client'));
        $fetcher = new FakeRequestObjectFetcher();
        $fetcher->failure = new RequestObjectUnavailableException('The client answered 500.');
        $resolver = RequestObjects::resolver($this->clients, $this->clock, $fetcher);

        // When / Then
        $this->refuses(
            [
                'client_id' => 'reference-client',
                'request_uri' => self::PUBLISHED,
            ],
            'invalid_request_uri',
            'The request object behind the request_uri parameter cannot be read back.',
            $resolver,
        );
    }

    /**
     * RFC 9101 §6.2: a client whose keys cannot be read has no request object that verifies.
     */
    #[Test]
    public function anObjectOfAClientWhoseKeysCannotBeReadIsRefused(): void
    {
        // Given
        $this->clients->save(Clients::withKeys($this->tenant, 'unreadable-client', jwksUri: new ClientUri('https://key.example/jwks')));
        $jwks = new FakeClientJwksFetcher([ClientAssertions::publishedKeys()]);
        $jwks->failure = new ClientKeysUnavailableException('The jwks_uri answered 500.');
        $resolver = RequestObjects::resolver($this->clients, $this->clock, null, Methods::keySetProvider($jwks, $this->clock, new DateInterval('PT0S')));
        $object = RequestObjects::signed(RequestObjects::claims('unreadable-client', $this->tenant->issuer->value, $this->clock->now()));

        // When / Then
        $this->refuses(
            [
                'client_id' => 'unreadable-client',
                'request' => $object,
            ],
            'invalid_request_object',
            'The keys of the client cannot be read, and its request object cannot be verified.',
            $resolver,
        );
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private function refuses(array $parameters, string $error, string $description, ?RequestObjectResolver $resolver = null): void
    {
        // When
        try {
            ($resolver ?? $this->resolver)->resolve($this->tenant, $parameters);
            static::fail('The request should have been refused.');
        } catch (OAuth2Exception $exception) {
            // Then
            static::assertSame($error, $exception->error);
            static::assertSame($description, $exception->errorDescription);
            static::assertFalse($exception->redirectable);
        }
    }
}
