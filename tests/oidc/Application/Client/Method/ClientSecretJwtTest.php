<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client\Method;

use function count;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Client\AuthenticatedClient;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Tests\Fixture\ClientAssertions;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * "client_secret_jwt" (OIDC Core §9): the same assertion as "private_key_jwt", signed with the secret the
 * client registered, HS256 and nothing else.
 */
final class ClientSecretJwtTest extends TestCase
{
    private const string ENDPOINT = 'https://id.acme.example/token';

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
        $this->client = Clients::withSharedSecret($this->tenant);
        $this->clients->save($this->client);
        $this->clients->save(Clients::withKeys($this->tenant));
    }

    #[Test]
    public function itAuthenticatesAClientThatSignsWithItsRegisteredSecret(): void
    {
        // When
        $client = $this->authenticate($this->assertion());

        // Then
        static::assertSame($this->client, $client->client);
    }

    /**
     * The secret is what signs, so the hasher is never asked anything.
     */
    #[Test]
    public function itVerifiesNothingAgainstAHash(): void
    {
        // When
        $this->authenticate($this->assertion());

        // Then
        static::assertSame([], $this->hasher->verifiedAgainst);
    }

    #[Test]
    public function itRefusesAMacMadeWithAnotherSecret(): void
    {
        // Given
        $assertion = ClientAssertions::signedWithSecret(ClientAssertions::claims($this->client->clientId, self::ENDPOINT, $this->context->receivedAt), 'not ' . Clients::SECRET);

        // When
        $exception = $this->failToAuthenticate($assertion);

        // Then
        static::assertInstanceOf(InvalidClientException::class, $exception);
        static::assertSame('Client authentication failed.', $exception->errorDescription);
        $this->assertRefused(ClientAuthenticationFailureReason::InvalidAssertion);
    }

    /**
     * RFC 7523 §4: an assertion authenticates once, whatever signs it.
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
     * The two assertion methods are told apart by what signs the assertion: a client registered for one
     * and sending the other is refused like a client sending a secret it did not register.
     */
    #[Test]
    public function aClientRegisteredForPrivateKeyJwtCannotSignWithASecretInstead(): void
    {
        // Given
        $keyClient = Clients::withKeys($this->tenant);
        $assertion = ClientAssertions::signedWithSecret(ClientAssertions::claims($keyClient->clientId, self::ENDPOINT, $this->context->receivedAt), Clients::SECRET);

        // When
        $exception = $this->failToAuthenticate($assertion);

        // Then
        static::assertInstanceOf(InvalidClientException::class, $exception);
        $this->assertRefused(ClientAuthenticationFailureReason::UnexpectedMethod, $keyClient->clientId);
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function assertion(array $overrides = []): string
    {
        return ClientAssertions::signedWithSecret(ClientAssertions::claims($this->client->clientId, self::ENDPOINT, $this->context->receivedAt, $overrides), Clients::SECRET);
    }

    private function authenticator(): ClientAuthenticator
    {
        return new ClientAuthenticator($this->clients, Methods::all($this->hasher), new MockClock('2026-09-15T10:00:00+00:00'), $this->events);
    }

    private function authenticate(string $assertion): AuthenticatedClient
    {
        return $this->authenticator()
            ->authenticate($this->tenant, self::ENDPOINT, null, ClientAssertions::parameters($assertion), $this->context);
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

    private function assertRefused(ClientAuthenticationFailureReason $reason, ?string $clientId = null): void
    {
        $events = $this->events->of(ClientAuthenticationFailed::class);
        $last = $events[count($events) - 1];
        static::assertSame($reason, $last->reason);
        static::assertSame($clientId ?? $this->client->clientId, $last->clientId);
        static::assertSame('client_secret_jwt', $last->method);
    }
}
