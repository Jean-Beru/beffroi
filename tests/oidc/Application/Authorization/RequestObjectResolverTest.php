<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Authorization;

use function array_map;
use DateInterval;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Authorization\RequestObjectResolver;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Client\RequestUri;
use Beffroi\Oidc\Domain\Client\RequestObject\OneRegisteredAlgorithm;
use Beffroi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Exception\RequestObjectUnavailableException;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeClientJwksFetcher;
use Beffroi\Oidc\Tests\Fixture\FakeRequestObjectFetcher;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\RequestObjects;
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

    #[Test]
    public function aRequestWithoutAnObjectIsLeftAlone(): void
    {
        // When
        $parameters = $this->resolver->resolve($this->tenant, [
            'client_id' => 'jar-client',
            'scope' => 'openid',
        ])?->parameters;

        // Then
        static::assertNull($parameters);
    }

    /**
     * OIDC Core §6.1
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
        ])?->parameters;

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
     * RFC 9126 §2
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
        )?->parameters;

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
     * OIDC Core §6
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
     * RFC 9101 §5
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
     * RFC 9101 §6.2
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
     * OIDC Registration §2
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
     * Decision 0006
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
     * OIDC Registration §2, decision 0006
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
        ])?->parameters;

        // Then
        static::assertSame('form_post', $parameters['response_mode'] ?? null);
        static::assertSame('unsigned-client', $parameters['client_id'] ?? null);
    }

    /**
     * OIDC Discovery §3
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
     * OIDC Core §6.2
     */
    #[Test]
    public function theObjectBehindARegisteredReferenceIsReadBack(): void
    {
        // Given
        $this->clients->save(Clients::sendingRequestObjects($this->tenant, requestUris: [new RequestUri(self::PUBLISHED)], clientId: 'reference-client'));
        $object = RequestObjects::signed(RequestObjects::claims('reference-client', $this->tenant->issuer->value, $this->clock->now(), [
            'scope' => 'openid profile',
        ]));
        $fetcher = new FakeRequestObjectFetcher($object);
        $resolver = RequestObjects::resolver($this->clients, $this->clock, $fetcher);

        // When
        $parameters = $resolver->resolve($this->tenant, [
            'client_id' => 'reference-client',
            'request_uri' => self::PUBLISHED,
        ])?->parameters;

        // Then
        static::assertSame('openid profile', $parameters['scope'] ?? null);
        static::assertSame([self::PUBLISHED], array_map(static fn (ClientUri $uri): string => $uri->value, $fetcher->fetched));
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aReferenceThatCannotBeReadBackIsRefused(): void
    {
        // Given
        $this->clients->save(Clients::sendingRequestObjects($this->tenant, requestUris: [new RequestUri(self::PUBLISHED)], clientId: 'reference-client'));
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
     * RFC 9101 §6.2
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
