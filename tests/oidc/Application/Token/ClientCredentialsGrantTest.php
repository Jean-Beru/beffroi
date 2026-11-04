<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Application\Token\ClientCredentialsGrant;
use Beffroi\Oidc\Application\Token\TokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\ClientAuthorization;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\InvalidScopeException;
use Beffroi\Oidc\Exception\InvalidTargetException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class ClientCredentialsGrantTest extends TestCase
{
    private Tenant $tenant;

    private Client $client;

    private RequestContext $context;

    private FakeIdTokenIssuer $idTokens;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private RecordingEventDispatcher $events;

    private ClientCredentialsGrant $grant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->client = Clients::service($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $clock = new MockClock('2026-09-15T12:00:00+00:00');
        $this->context = Fixtures::context($clock->now());
        $this->idTokens = new FakeIdTokenIssuer();
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->events = new RecordingEventDispatcher();
        $this->grant = new ClientCredentialsGrant(
            new TokenIssuer(new FakeAccessTokenIssuer(), $this->idTokens, $this->refreshTokens, Secrets::drawer(), $this->events),
            new SymfonyUuidGenerator(),
            $clock,
        );
    }

    #[Test]
    public function itHandlesTheClientCredentialsGrantType(): void
    {
        // When / Then
        static::assertTrue($this->grant->grantType()->equals(Grants::clientCredentials()));
    }

    /**
     * RFC 6749 §4.4, RFC 8707 §2
     */
    #[Test]
    public function itAuthorizesTheClientForItselfAndForTheResourceAsked(): void
    {
        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        $authorization = $issued->authorization;
        static::assertNotInstanceOf(UserAuthorizationInterface::class, $authorization, 'nobody signed in for it');
        static::assertInstanceOf(ClientAuthorization::class, $authorization);
        static::assertSame($this->client, $authorization->client);
        static::assertTrue($authorization->grantType->equals(Grants::clientCredentials()));
        static::assertSame(['invoices.read'], $authorization->scopes->values());
        static::assertSame([Clients::CALENDAR], $authorization->resources->values());
        static::assertSame([Clients::CALENDAR], $authorization->audience()->values);
    }

    /**
     * RFC 6749 §4.4.3
     */
    #[Test]
    public function theResponseCarriesNoIdTokenAndNoRefreshToken(): void
    {
        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(scope: 'invoices.read invoices.write'), $this->context);

        // Then
        static::assertNull($issued->idToken);
        static::assertNull($issued->refreshToken);
        static::assertSame([], $this->idTokens->issued);
        static::assertSame([], $this->refreshTokens->all());
        static::assertSame('Bearer', $issued->toResponse()->parameters()['token_type']);
    }

    /**
     * OIDC Core §2
     */
    #[Test]
    public function itRefusesTheOpenidScope(): void
    {
        // Given
        $client = Clients::service(
            $this->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            allowedScopes: new Scopes([Scope::openid(), new Scope('invoices.read')]),
        );

        // Then
        $this->expectException(InvalidScopeException::class);
        $this->expectExceptionMessageIs('invalid_scope: The openid scope asks for an authentication, and this grant has no user to authenticate (OIDC Core section 2).');

        // When
        $this->grant->grant(new AuthenticatedClient($client), $this->request(scope: 'openid'), $this->context);
    }

    /**
     * RFC 6749 §4.4.2, §5.2
     */
    #[Test]
    public function itRefusesAScopeTheClientDidNotRegister(): void
    {
        // Then
        $this->expectException(InvalidScopeException::class);
        $this->expectExceptionMessageIs('invalid_scope: The requested scope is not allowed for this client.');

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(scope: 'payroll.read'), $this->context);
    }

    /**
     * RFC 6749 §3.3
     */
    #[Test]
    public function itRefusesAScopeThatIsNotAListOfScopeTokens(): void
    {
        // Then
        $this->expectException(InvalidScopeException::class);
        $this->expectExceptionMessageIs('invalid_scope: The scope parameter is not a space-separated list of scope tokens (RFC 6749 section 3.3).');

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(scope: "invoices.read\tinvoices.write"), $this->context);
    }

    /**
     * RFC 6749 §5.2
     */
    #[Test]
    public function itRefusesARequestThatNamesNoScope(): void
    {
        // Given
        $request = RequestParameters::of([
            'grant_type' => 'client_credentials',
            'resource' => Clients::CALENDAR,
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $request, $this->context);
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    public function itRefusesARequestThatNamesNoResource(): void
    {
        // Given
        $request = RequestParameters::of([
            'grant_type' => 'client_credentials',
            'scope' => 'invoices.read',
        ]);

        // Then
        $this->expectException(InvalidTargetException::class);
        $this->expectExceptionMessageIs('invalid_target: This grant type issues an access token for a resource, and the request names none (RFC 8707 section 2).');

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $request, $this->context);
    }

    /**
     * RFC 8707 §2.1
     *
     * @param string|list<string> $resource
     */
    #[Test]
    #[DataProvider('provideResourcesTheClientMayNotAskFor')]
    public function itRefusesAResourceTheClientDidNotRegister(string|array $resource): void
    {
        // Then
        $this->expectException(InvalidTargetException::class);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(resource: $resource), $this->context);
    }

    /**
     * @return iterable<string, array{string|list<string>}>
     */
    public static function provideResourcesTheClientMayNotAskFor(): iterable
    {
        yield 'another resource' => ['https://payroll.example.com/'];
        yield 'one registered and one not' => [[Clients::CALENDAR, 'https://payroll.example.com/']];
        yield 'not an absolute URI' => ['/calendar'];
    }

    #[Test]
    public function theTokensAreAnnouncedWithoutASession(): void
    {
        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        $event = $this->events->of(TokensIssued::class)[0] ?? static::fail('The tokens were announced.');
        static::assertNull($event->sessionId);
        static::assertSame('batch', $event->clientId);
        static::assertTrue($event->grantType->equals(Grants::clientCredentials()));
        static::assertFalse($event->idTokenIssued);
        static::assertNull($event->refreshTokenHash);
        static::assertSame($this->context, $event->context);
    }

    /**
     * @param string|list<string> $resource
     */
    private function request(string $scope = 'invoices.read', string|array $resource = Clients::CALENDAR): RequestParameters
    {
        return RequestParameters::of([
            'grant_type' => 'client_credentials',
            'scope' => $scope,
            'resource' => $resource,
        ]);
    }
}
