<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use function base64_encode;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Application\Token\AuthorizationCodeGrant;
use Heidi\Oidc\Application\Token\RefreshTokenGrant;
use Heidi\Oidc\Application\Token\TokenHandler;
use Heidi\Oidc\Application\Token\TokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Heidi\Oidc\Domain\Event\RefreshTokenRotated;
use Heidi\Oidc\Domain\Event\TokensIssued;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\UnauthorizedClientException;
use Heidi\Oidc\Exception\UnsupportedGrantTypeException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Heidi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Heidi\Oidc\Tests\Fixture\FakePasswordHasher;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class TokenHandlerTest extends TestCase
{
    private Tenant $tenant;

    private Client $basicClient;

    private Client $postClient;

    private Client $publicClient;

    private AuthenticationSession $session;

    private RequestContext $context;

    private MockClock $clock;

    private FakePasswordHasher $hasher;

    private InMemoryClientRepository $clients;

    private InMemoryAuthorizationCodeRepository $codes;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private RecordingEventDispatcher $events;

    private AuthorizationCodeGrant $codeGrant;

    private TokenHandler $handler;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $alice = Fixtures::user($this->tenant);
        $this->hasher = new FakePasswordHasher();
        $this->basicClient = Clients::confidential($this->tenant, $this->hasher->hash(Clients::SECRET), TokenEndpointAuthMethod::ClientSecretBasic, 'basic-client');
        $this->postClient = Clients::confidential($this->tenant, $this->hasher->hash(Clients::SECRET), TokenEndpointAuthMethod::ClientSecretPost, 'post-client');
        $this->publicClient = Clients::public($this->tenant, 'public-client');
        $this->clients = new InMemoryClientRepository();
        foreach ([$this->basicClient, $this->postClient, $this->publicClient] as $client) {
            $this->clients->save($client);
        }
        $this->clock = new MockClock('2026-09-15T12:00:00+00:00');
        $this->session = Fixtures::session($alice, $this->clock->now()->modify('-1 hour'));
        $this->context = Fixtures::context($this->clock->now());
        $this->codes = new InMemoryAuthorizationCodeRepository();
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->events = new RecordingEventDispatcher();
        $issuer = new TokenIssuer(new FakeAccessTokenIssuer(), new FakeIdTokenIssuer(), $this->refreshTokens, $this->events);
        $this->codeGrant = new AuthorizationCodeGrant($this->codes, $this->refreshTokens, $issuer, $this->clock, $this->events);
        $refreshGrant = new RefreshTokenGrant($this->refreshTokens, $issuer, $this->clock, $this->events);
        $this->handler = new TokenHandler($this->authenticator(), [$this->codeGrant, $refreshGrant]);
    }

    /**
     * RFC 6749 §4.1.3 and §5.1 end to end, the way oidc_login sends it: client_secret_basic with the
     * client_id repeated in the body.
     */
    #[Test]
    public function itExchangesACodeForTokens(): void
    {
        $code = Tokens::code('the-code', $this->basicClient, $this->session, $this->clock->now(), ['openid', 'profile']);
        $this->codes->save($code);

        $response = $this->handler->handle($this->tenant, self::basic('basic-client', Clients::SECRET), [
            'grant_type' => 'authorization_code',
            'code' => 'the-code',
            'redirect_uri' => 'https://demo.localhost/login/check',
            'client_id' => 'basic-client',
            'code_verifier' => Tokens::CODE_VERIFIER,
        ], $this->context);

        $parameters = $response->parameters();
        static::assertSame('at:basic-client:alice-subject:' . $this->clock->now()->getTimestamp(), $parameters['access_token']);
        static::assertSame('Bearer', $parameters['token_type']);
        static::assertSame(600, $parameters['expires_in']);
        static::assertSame('id:basic-client:alice-subject:n-0S6_WzA2Mj:' . $this->clock->now()->getTimestamp(), $parameters['id_token']);
        static::assertSame('openid profile', $parameters['scope']);
        static::assertArrayHasKey('refresh_token', $parameters);
        static::assertTrue($code->isUsed());
        static::assertCount(1, $this->refreshTokens->all());
        static::assertCount(1, $this->events->of(TokensIssued::class));
    }

    /**
     * RFC 6749 §6 end to end with client_secret_post.
     */
    #[Test]
    public function itRefreshesTokens(): void
    {
        $token = Tokens::refreshToken('the-token', $this->postClient, $this->session, $this->clock->now(), null, ['openid', 'profile']);
        $this->refreshTokens->save($token);

        $response = $this->handler->handle($this->tenant, null, [
            'grant_type' => 'refresh_token',
            'refresh_token' => 'the-token',
            'client_id' => 'post-client',
            'client_secret' => Clients::SECRET,
        ], $this->context);

        $parameters = $response->parameters();
        static::assertSame('id:post-client:alice-subject:-:' . $this->clock->now()->getTimestamp(), $parameters['id_token']);
        static::assertArrayHasKey('refresh_token', $parameters);
        static::assertNotSame('the-token', $parameters['refresh_token']);
        static::assertTrue($token->isRotated());
        static::assertCount(1, $this->events->of(RefreshTokenRotated::class));
    }

    /**
     * RFC 6749 §3.2.1: the client is authenticated before anything else is read, so that a caller that
     * is not a client learns nothing about the request; the failure is announced.
     */
    #[Test]
    public function itAuthenticatesTheClientBeforeReadingTheGrant(): void
    {
        $code = Tokens::code('the-code', $this->basicClient, $this->session, $this->clock->now());
        $this->codes->save($code);

        try {
            $this->handler->handle($this->tenant, self::basic('basic-client', 'wrong-secret'), [
                'code' => 'the-code',
            ], $this->context);
            static::fail('The client should have been refused.');
        } catch (InvalidClientException $exception) {
            static::assertSame(401, $exception->statusCode);
            static::assertSame('Basic realm="https://id.acme.example"', $exception->challenge);
        }
        static::assertFalse($code->isUsed());
        static::assertCount(1, $this->events->of(ClientAuthenticationFailed::class));
        static::assertCount(1, $this->events->events);
    }

    /**
     * RFC 6749 §4.1.3, §6: "grant_type" is required.
     */
    #[Test]
    public function itRequiresAGrantType(): void
    {
        foreach ([[], [
            'grant_type' => '',
        ], [
            'grant_type' => ['authorization_code'],
        ]] as $parameters) {
            try {
                $this->handler->handle($this->tenant, self::basic('basic-client', Clients::SECRET), $parameters, $this->context);
                static::fail('The grant type is required.');
            } catch (InvalidRequestException $exception) {
                static::assertStringContainsString('grant_type', $exception->errorDescription);
            }
        }
    }

    /**
     * RFC 6749 §5.2 "unsupported_grant_type": the grants of decision 0006 only, and only those the
     * handler was given.
     */
    #[Test]
    public function itRefusesAGrantTypeTheProviderDoesNotServe(): void
    {
        $codeOnly = new TokenHandler($this->authenticator(), [$this->codeGrant]);

        foreach (['password', 'client_credentials', 'implicit', 'urn:ietf:params:oauth:grant-type:device_code', 'Authorization_Code'] as $grantType) {
            try {
                $this->handler->handle($this->tenant, self::basic('basic-client', Clients::SECRET), [
                    'grant_type' => $grantType,
                ], $this->context);
                static::fail($grantType . ' is not supported.');
            } catch (UnsupportedGrantTypeException $exception) {
                static::assertSame(400, $exception->statusCode);
            }
        }
        try {
            $codeOnly->handle($this->tenant, null, [
                'grant_type' => 'refresh_token',
                'client_id' => 'public-client',
            ], $this->context);
            static::fail('refresh_token is not served by this handler.');
        } catch (UnsupportedGrantTypeException $exception) {
            static::assertSame(400, $exception->statusCode);
        }
    }

    /**
     * RFC 6749 §5.2 "unauthorized_client": the client is authenticated but not registered for the grant.
     */
    #[Test]
    public function itRefusesAGrantTheClientIsNotRegisteredFor(): void
    {
        $token = Tokens::refreshToken('the-token', $this->publicClient, $this->session, $this->clock->now());
        $this->refreshTokens->save($token);

        try {
            $this->handler->handle($this->tenant, null, [
                'grant_type' => 'refresh_token',
                'refresh_token' => 'the-token',
                'client_id' => 'public-client',
            ], $this->context);
            static::fail('The public client is not registered for refresh_token.');
        } catch (UnauthorizedClientException $exception) {
            static::assertSame(400, $exception->statusCode);
            static::assertFalse($exception->redirectable);
        }
        static::assertFalse($token->isRotated());
    }

    #[Test]
    public function itRefusesTwoGrantsForTheSameType(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new TokenHandler($this->authenticator(), [$this->codeGrant, $this->codeGrant]);
    }

    private function authenticator(): ClientAuthenticator
    {
        return new ClientAuthenticator($this->clients, $this->hasher, $this->clock, $this->events);
    }

    private static function basic(string $clientId, string $secret): string
    {
        return 'Basic ' . base64_encode($clientId . ':' . $secret);
    }
}
