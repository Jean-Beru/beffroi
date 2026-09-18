<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Introspection;

use function base64_encode;
use DateTimeImmutable;
use Heidi\Core\Bridge\InMemory\InMemoryUserRepository;
use Heidi\Core\Bridge\JwtFramework\JwtFrameworkJwsVerifier;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Application\Introspection\IntrospectionHandler;
use Heidi\Oidc\Application\Token\AccessTokenInspector;
use Heidi\Oidc\Application\Token\AccessTokenVerifier;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakePasswordHasher;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\Tokens;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * The endpoint end to end below HTTP: tokens of both shapes, a real client authentication, the response
 * signed by the bridge of the core and verified the way Symfony's Oauth2TokenHandler verifies it.
 */
final class IntrospectionHandlerTest extends TestCase
{
    private Tenant $tenant;

    private AuthenticationSession $session;

    private Client $client;

    private Client $other;

    private MockClock $clock;

    private RequestContext $context;

    private Jwts $jwts;

    private InMemoryAuthorizationCodeRepository $grants;

    private InMemoryAccessTokenRepository $tokens;

    private IntrospectionHandler $handler;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $user = Fixtures::user($this->tenant);
        $this->clock = new MockClock('2026-09-17T12:00:00+00:00');
        $this->context = Fixtures::context($this->clock->now());
        $this->session = Fixtures::session($user, $this->clock->now()->modify('-1 hour'));
        $hasher = new FakePasswordHasher();
        $this->client = Clients::confidential($this->tenant, $hasher->hash(Clients::SECRET), accessTokenFormat: AccessTokenFormat::Opaque);
        $this->other = Clients::confidential($this->tenant, $hasher->hash(Clients::SECRET), TokenEndpointAuthMethod::ClientSecretPost, 'other');
        $clients = new InMemoryClientRepository();
        foreach ([$this->client, $this->other, Clients::public($this->tenant)] as $client) {
            $clients->save($client);
        }
        $this->jwts = new Jwts($this->tenant);
        $this->grants = new InMemoryAuthorizationCodeRepository();
        $this->tokens = new InMemoryAccessTokenRepository();
        $users = new InMemoryUserRepository();
        $users->save($user);
        $this->handler = new IntrospectionHandler(
            new ClientAuthenticator($clients, $hasher, $this->clock, new RecordingEventDispatcher()),
            new AccessTokenInspector(new AccessTokenVerifier(new JwtFrameworkJwsVerifier($this->jwts->keys), $clients, $this->tokens, new PublicSubjectIdentifierResolver()), $this->grants, $users),
            $this->jwts->signer,
        );
    }

    /**
     * RFC 7662 §2.2: an opaque token of the caller, described from its record.
     */
    #[Test]
    public function itDescribesAnOpaqueTokenToTheClientItWasIssuedTo(): void
    {
        // Given
        $code = $this->code($this->client, ['openid', 'email']);
        $token = $this->opaqueToken($code);

        // When
        $response = $this->handler->handle($this->tenant, self::basic('oidc-demo'), [
            'token' => $token,
            'token_type_hint' => 'access_token',
        ], $this->context, false);

        // Then
        static::assertSame([
            'active' => true,
            'scope' => 'openid email',
            'client_id' => 'oidc-demo',
            'token_type' => 'Bearer',
            'exp' => $this->clock->now()
                ->modify('+10 minutes')
                ->getTimestamp(),
            'iat' => $this->clock->now()
                ->getTimestamp(),
            'sub' => 'alice-subject',
            'aud' => 'oidc-demo',
            'iss' => 'https://id.acme.example',
            'auth_time' => $this->session->authenticatedAt()
                ->getTimestamp(),
            'acr' => '1',
            'amr' => ['pwd'],
            'sid' => $this->session->id->toRfc4122(),
            'grant_id' => $code->grantId->toRfc4122(),
        ], $response->members);
        static::assertNull($response->jwt);
    }

    /**
     * RFC 7662 §2.2: a self-contained token is described the same way, from its claims, for a resource
     * server that would rather not verify it itself.
     */
    #[Test]
    public function itDescribesAJwtTokenAsWell(): void
    {
        // Given
        $code = $this->code($this->other, ['openid']);
        $token = new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver())
            ->issue(GrantedAuthorization::fromAuthorizationCode($code), $this->clock->now())
            ->value;

        // When
        $response = $this->handler->handle($this->tenant, null, [
            'client_id' => 'other',
            'client_secret' => Clients::SECRET,
            'token' => $token,
        ], $this->context, false);

        // Then
        static::assertTrue($response->isActive());
        static::assertSame('other', $response->members['client_id']);
        static::assertSame('alice-subject', $response->members['sub']);
        static::assertSame($code->grantId->toRfc4122(), $response->members['grant_id']);
    }

    /**
     * RFC 7662 §2.2 and §4: a token that is not the caller's, or not one to honour, is "active": false and
     * nothing else, whatever the reason.
     *
     * @param callable(self): string $token
     */
    #[Test]
    #[DataProvider('provideInactiveTokens')]
    public function itSaysNothingOfATokenTheCallerMayNotHonour(callable $token): void
    {
        // Given
        $value = $token($this);

        // When
        $response = $this->handler->handle($this->tenant, self::basic('oidc-demo'), [
            'token' => $value,
        ], $this->context, false);

        // Then
        static::assertSame([
            'active' => false,
        ], $response->members);
    }

    /**
     * @return iterable<string, array{callable(self): string}>
     */
    public static function provideInactiveTokens(): iterable
    {
        yield 'unknown' => [
            static fn (): string => 'unknown',
        ];
        yield 'of another client' => [
            static fn (self $test): string => $test->opaqueToken($test->code($test->other)),
        ];
        yield 'expired' => [
            static fn (self $test): string => $test->opaqueToken($test->code($test->client), $test->clock->now()->modify('-10 minutes')),
        ];
        yield 'of a revoked grant' => [static function (self $test): string {
            $code = $test->code($test->client);
            $token = $test->opaqueToken($code);
            $code->revoke($test->clock->now());

            return $token;
        }];
        yield 'of a disabled user' => [static function (self $test): string {
            $token = $test->opaqueToken($test->code($test->client));
            $test->session->user->disable($test->clock->now());

            return $token;
        }];
        yield 'a JWT of another issuer' => [
            static fn (): string => 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkLm90aGVyLmV4YW1wbGUifQ.c2ln',
        ];
    }

    /**
     * RFC 7662 §2.1: the caller authenticates as a client; a wrong secret is invalid_client, 401, with the
     * challenge of the token endpoint.
     */
    #[Test]
    public function itRefusesACallerThatDoesNotAuthenticate(): void
    {
        // When
        try {
            $this->handler->handle($this->tenant, self::basic('oidc-demo', 'wrong'), [
                'token' => 'whatever',
            ], $this->context, false);
            static::fail('The caller should have been refused.');
        } catch (InvalidClientException $exception) {
            // Then
            static::assertSame(401, $exception->statusCode);
            static::assertSame('Basic realm="https://id.acme.example"', $exception->challenge);
        }
    }

    /**
     * RFC 7662 §2.1: a public client has nothing to authenticate with, and the endpoint requires it
     * against token scanning.
     */
    #[Test]
    public function itRefusesAPublicClient(): void
    {
        // Then
        $this->expectException(InvalidClientException::class);
        $this->expectExceptionMessageIs('invalid_client: The introspection endpoint requires client authentication (RFC 7662 section 2.1); a public client has none.');

        // When
        $this->handler->handle($this->tenant, null, [
            'client_id' => 'spa',
            'token' => 'whatever',
        ], $this->context, false);
    }

    /**
     * RFC 7662 §2.1: "token" is required; a hint that is not a string is not read either.
     *
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('provideMalformedRequests')]
    public function itRefusesAMalformedRequest(array $parameters, string $message): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: ' . $message);

        // When
        $this->handler->handle($this->tenant, self::basic('oidc-demo'), $parameters, $this->context, false);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideMalformedRequests(): iterable
    {
        yield 'no token' => [[], 'The token parameter is missing.'];
        yield 'empty token' => [[
            'token' => '',
        ], 'The token parameter is missing.'];
        yield 'token repeated' => [[
            'token' => ['a', 'b'],
        ], 'The token parameter must be a single string.'];
        yield 'hint repeated' => [[
            'token' => 'a',
            'token_type_hint' => ['access_token'],
        ], 'The token_type_hint parameter must be a single string.'];
    }

    /**
     * RFC 9701 §4 and §5: when asked, the members travel as the "token_introspection" claim of a JWT that
     * names the provider, the caller and the moment, signed with the active key under the "typ" of §5,
     * which is what Symfony's Oauth2TokenHandler checks before reading the members.
     */
    #[Test]
    public function itSignsTheResponseWhenAsked(): void
    {
        // Given
        $code = $this->code($this->client);
        $token = $this->opaqueToken($code);

        // When
        $response = $this->handler->handle($this->tenant, self::basic('oidc-demo'), [
            'token' => $token,
        ], $this->context, true);

        // Then
        $jwt = $response->jwt ?? static::fail('The response is signed.');
        $jws = new CompactSerializer()
            ->unserialize($jwt);
        static::assertTrue(new JWSVerifier(new AlgorithmManager([new RS256()]))->verifyWithKeySet($jws, JWKSet::createFromKeyData($this->jwts->keys->publicKeys($this->tenant)->toJwks()), 0));
        static::assertSame('token-introspection+jwt', $jws->getSignature(0)->getProtectedHeaderParameter('typ'));
        static::assertSame($this->jwts->key->kid, $jws->getSignature(0)->getProtectedHeaderParameter('kid'));
        $claims = Jwts::decode((string) $jws->getPayload());
        static::assertSame('https://id.acme.example', $claims['iss']);
        static::assertSame('oidc-demo', $claims['aud']);
        static::assertSame($this->clock->now()->getTimestamp(), $claims['iat']);
        static::assertSame($response->members, $claims['token_introspection']);
        static::assertTrue($response->isActive());
    }

    /**
     * RFC 9701 §5: an inactive token is signed too; the caller asked for a JWT and gets one.
     */
    #[Test]
    public function anInactiveTokenIsSignedToo(): void
    {
        // When
        $response = $this->handler->handle($this->tenant, self::basic('oidc-demo'), [
            'token' => 'unknown',
        ], $this->context, true);

        // Then
        $jwt = $response->jwt ?? static::fail('The response is signed.');
        static::assertSame([
            'active' => false,
        ], Jwts::decode(Jwts::rawPayload($jwt))['token_introspection']);
    }

    /**
     * @param list<string> $scopes
     */
    private function code(Client $client, array $scopes = ['openid']): AuthorizationCode
    {
        $code = Tokens::code('the-code-of-' . $client->clientId, $client, $this->session, $this->clock->now(), $scopes);
        $this->grants->save($code);

        return $code;
    }

    private function opaqueToken(AuthorizationCode $code, ?DateTimeImmutable $issuedAt = null): string
    {
        $issuedAt ??= $this->clock->now();

        return $this->tokens->issue(GrantedAuthorization::fromAuthorizationCode($code), $issuedAt, $issuedAt->modify('+10 minutes'));
    }

    private static function basic(string $clientId, string $secret = Clients::SECRET): string
    {
        return 'Basic ' . base64_encode($clientId . ':' . $secret);
    }
}
