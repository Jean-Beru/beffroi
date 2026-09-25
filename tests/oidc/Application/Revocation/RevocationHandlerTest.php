<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Revocation;

use Heidi\Oidc\Tests\Fixture\Secrets;
use Heidi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Heidi\Oidc\Tests\Fixture\FakeClientLoadBudget;
use Heidi\Oidc\Tests\Fixture\Grants;
use function base64_encode;
use DateTimeImmutable;
use Heidi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Application\Revocation\RevocationHandler;
use Heidi\Oidc\Tests\Fixture\AccessTokenShapes;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Event\TokenRevoked;
use Heidi\Oidc\Domain\Token\UserAuthorization;
use Heidi\Oidc\Domain\Token\StoredUserAccessToken;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\UnsupportedTokenTypeException;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Endpoints;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\Methods;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Clock\MockClock;

final class RevocationHandlerTest extends TestCase
{
    private Tenant $tenant;

    private AuthenticationSession $session;

    private Client $client;

    private Client $other;

    private Client $public;

    private MockClock $clock;

    private RequestContext $context;

    private Jwts $jwts;

    private InMemoryAccessTokenRepository $accessTokens;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private RecordingEventDispatcher $events;

    private RevocationHandler $handler;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clock = new MockClock('2026-09-17T12:00:00+00:00');
        $this->context = Fixtures::context($this->clock->now());
        $this->session = Fixtures::session(Fixtures::user($this->tenant), $this->clock->now()->modify('-1 hour'));
        $hasher = new FakePasswordHasher();
        $this->client = Clients::confidential($this->tenant, $hasher->hash(Clients::SECRET));
        $this->other = Clients::confidential($this->tenant, $hasher->hash(Clients::SECRET), Methods::clientSecretPost(), 'other');
        $this->public = Clients::public($this->tenant);
        $clients = new InMemoryClientRepository();
        foreach ([$this->client, $this->other, $this->public] as $client) {
            $clients->save($client);
        }
        $this->jwts = new Jwts($this->tenant);
        $this->accessTokens = new InMemoryAccessTokenRepository();
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->events = new RecordingEventDispatcher();
        $this->handler = $this->handler($clients, $hasher, $this->accessTokens);
    }

    /**
     * RFC 7009 §2.1: an opaque access token of the caller is gone, and the revocation is announced.
     */
    #[Test]
    public function itRevokesAnAccessTokenOfTheCaller(): void
    {
        // Given
        $token = $this->accessToken($this->client);
        $record = $this->accessTokens->find($token) ?? static::fail('The token was kept.');

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $token,
                'token_type_hint' => 'access_token',
            ],
            $this->context,
        );

        // Then
        static::assertNull($this->accessTokens->find($token));
        $events = $this->events->of(TokenRevoked::class);
        static::assertCount(1, $events);
        static::assertSame(TokenRevoked::ACCESS_TOKEN, $events[0]->tokenType);
        static::assertSame($record->tokenHash, $events[0]->tokenHash);
        static::assertSame($this->client->registration->clientId, $events[0]->revokedBy);
        static::assertSame([], $events[0]->revokedAccessTokenHashes);
        static::assertEquals($this->clock->now(), $events[0]->occurredAt);
        static::assertSame($this->context, $events[0]->context);
    }

    /**
     * RFC 7009 §2.1: a refresh token of the caller is revoked, with the opaque access tokens of its grant;
     * the family and the tokens of other grants are left alone.
     */
    #[Test]
    public function itRevokesARefreshTokenAndTheAccessTokensOfItsGrant(): void
    {
        // Given
        $family = Tokens::family($this->clock->now()->modify('-2 days'));
        $rotated = Tokens::refreshToken('rotated', $this->client, $this->session, $this->clock->now()->modify('-1 day'), $family);
        $rotated->rotate($this->clock->now()->modify('-1 hour'));
        $current = Tokens::refreshToken('current', $this->client, $this->session, $this->clock->now()->modify('-1 hour'), $family);
        $this->refreshTokens->save($rotated);
        $this->refreshTokens->save($current);
        $ofTheGrant = Tokens::storedAccessToken('of-the-grant', $this->client, $this->session, $this->clock->now(), $family->grantId);
        $ofAnotherGrant = Tokens::storedAccessToken('of-another-grant', $this->client, $this->session, $this->clock->now());
        $this->accessTokens->save($ofTheGrant);
        $this->accessTokens->save($ofAnotherGrant);

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => 'current',
                'token_type_hint' => 'refresh_token',
            ],
            $this->context,
        );

        // Then
        static::assertTrue($current->isRevoked());
        static::assertEquals($this->clock->now(), $current->revokedAt);
        static::assertFalse($rotated->isRevoked(), 'the family is not revoked; a reuse of the rotated token is still told apart');
        static::assertSame([$ofAnotherGrant], $this->accessTokens->all());
        $events = $this->events->of(TokenRevoked::class);
        static::assertCount(1, $events);
        static::assertSame(TokenRevoked::REFRESH_TOKEN, $events[0]->tokenType);
        static::assertSame($current->tokenHash, $events[0]->tokenHash);
        static::assertSame([$ofTheGrant->tokenHash], $events[0]->revokedAccessTokenHashes);
    }

    /**
     * RFC 7009 §2.1: a public client may revoke what it holds.
     */
    #[Test]
    public function aPublicClientRevokesItsOwnToken(): void
    {
        // Given
        $token = $this->accessToken($this->public);

        // When
        $this->handler->handle(
            $this->tenant,
            null,
            [
                'client_id' => 'spa',
                'token' => $token,
            ],
            $this->context,
        );

        // Then
        static::assertNull($this->accessTokens->find($token));
    }

    /**
     * RFC 7009 §2.2: an invalid token, and a token of another client, are answered 200 with nothing
     * done and nothing said; the caller cannot learn that a token exists.
     *
     * @param callable(self): string $token
     */
    #[Test]
    #[DataProvider('provideTokensNotRevoked')]
    public function itDoesNothingForATokenItCannotRevokeForTheCaller(callable $token): void
    {
        // Given
        $value = $token($this);
        $accessTokensBefore = $this->accessTokens->all();

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $value,
            ],
            $this->context,
        );

        // Then
        static::assertSame($accessTokensBefore, $this->accessTokens->all());
        static::assertSame([], $this->events->of(TokenRevoked::class));
        foreach ($this->refreshTokens->all() as $refreshToken) {
            static::assertFalse($refreshToken->isRevoked());
        }
    }

    /**
     * @return iterable<string, array{callable(self): string}>
     */
    public static function provideTokensNotRevoked(): iterable
    {
        yield 'unknown' => [
            static fn (): string => 'unknown',
        ];
        yield 'a JWT that is not one of the provider' => [
            static fn (): string => 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkLm90aGVyLmV4YW1wbGUifQ.c2ln',
        ];
        yield 'an expired JWT of the provider' => [
            static fn (self $test): string => $test->jwt($test->client, $test->clock->now()->modify('-1 hour')),
        ];
    }

    /**
     * RFC 7009 §2.1: a token issued to another client is not the caller's to revoke; nothing is done and
     * nothing is said.
     */
    #[Test]
    public function anAccessTokenOfAnotherClientIsLeftAlone(): void
    {
        // Given
        $token = $this->accessToken($this->other);

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $token,
            ],
            $this->context,
        );

        // Then
        static::assertNotNull($this->accessTokens->find($token));
        static::assertSame([], $this->events->of(TokenRevoked::class));
    }

    #[Test]
    public function aRefreshTokenOfAnotherClientIsLeftAlone(): void
    {
        // Given
        $token = Tokens::refreshToken('theirs', $this->other, $this->session, $this->clock->now());
        $this->refreshTokens->save($token);

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => 'theirs',
            ],
            $this->context,
        );

        // Then
        static::assertFalse($token->isRevoked());
        static::assertSame([], $this->events->of(TokenRevoked::class));
    }

    /**
     * A refresh token already revoked is left as it was: its date, and the access tokens of its grant.
     */
    #[Test]
    public function aRefreshTokenAlreadyRevokedIsLeftAsItWas(): void
    {
        // Given
        $token = Tokens::refreshToken('revoked', $this->client, $this->session, $this->clock->now()->modify('-1 day'));
        $token->revoke($this->clock->now()->modify('-1 hour'));
        $this->refreshTokens->save($token);
        $this->accessTokens->save(Tokens::storedAccessToken('of-the-grant', $this->client, $this->session, $this->clock->now(), $token->family->grantId));

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => 'revoked',
            ],
            $this->context,
        );

        // Then
        static::assertEquals($this->clock->now()->modify('-1 hour'), $token->revokedAt);
        static::assertCount(1, $this->accessTokens->all());
        static::assertSame([], $this->events->of(TokenRevoked::class));
    }

    /**
     * RFC 7009 §2.2.1: a self-contained access token of the provider cannot be taken back, and the
     * endpoint says so rather than pretending.
     */
    #[Test]
    public function itRefusesToRevokeAJwtOfTheProvider(): void
    {
        // Given
        $token = $this->jwt($this->client, $this->clock->now());

        // Then
        $this->expectException(UnsupportedTokenTypeException::class);
        $this->expectExceptionMessageIs('unsupported_token_type: A self-contained access token cannot be revoked; it expires on its own (RFC 7009 section 2.2.1).');

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $token,
            ],
            $this->context,
        );
    }

    /**
     * RFC 7009 §2.2.1: a store that does not take tokens back makes the endpoint say so too.
     */
    #[Test]
    public function itRefusesToRevokeWhatTheStoreCannotTakeBack(): void
    {
        // Given
        $store = static::createStub(AccessTokenRepositoryInterface::class);
        $store
            ->method('find')
            ->willReturn(StoredUserAccessToken::fromAuthorization(
                str_repeat('a', 64),
                UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
                    'the-code',
                    $this->client,
                    $this->session,
                    $this->clock->now(),
                )),
                $this->clock->now(),
                $this->clock->now()->modify('+10 minutes'),
            ));
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);
        $handler = $this->handler($clients, new FakePasswordHasher(), $store);

        // Then
        $this->expectException(UnsupportedTokenTypeException::class);
        $this->expectExceptionMessageIs('unsupported_token_type: This provider does not take access tokens back; they expire on their own (RFC 7009 section 2.2.1).');

        // When
        $handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => 'whatever',
            ],
            $this->context,
        );
    }

    /**
     * RFC 7009 §2.1, RFC 6749 §2.3: the caller is authenticated as a client first.
     */
    #[Test]
    public function itRefusesACallerThatDoesNotAuthenticate(): void
    {
        // Then
        $this->expectException(InvalidClientException::class);

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo', 'wrong'),
            [
                'token' => 'whatever',
            ],
            $this->context,
        );
    }

    /**
     * RFC 7009 §2.1: "token" is required.
     */
    #[Test]
    public function itRequiresTheToken(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The token parameter is missing.');

        // When
        $this->handler->handle($this->tenant, self::basic('oidc-demo'), [], $this->context);
    }

    private function handler(InMemoryClientRepository $clients, FakePasswordHasher $hasher, AccessTokenRepositoryInterface $accessTokens): RevocationHandler
    {
        return new RevocationHandler(
            new ClientAuthenticator(
                $clients,
                Methods::all($hasher),
                Methods::requestParser(),
                $this->clock,
                new RecordingEventDispatcher(),
                new FakeClientLoadBudget(),
            ),
            new Endpoints(),
            AccessTokenShapes::verifier(
                new JwtLibraryJwsVerifier($this->jwts->keys, Algorithms::all()),
                $clients,
                $accessTokens,
                new PublicSubjectIdentifierResolver(),
            ),
            $accessTokens,
            $this->refreshTokens,
            $this->events,
        );
    }

    private function accessToken(Client $client): string
    {
        return new OpaqueAccessTokenIssuer($this->accessTokens, Secrets::drawer())->issue(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code('the-code', $client, $this->session, $this->clock->now())),
            $this->clock->now(),
        )->value;
    }

    private function jwt(Client $client, DateTimeImmutable $issuedAt): string
    {
        return new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), Algorithms::all(), new SymfonyUuidGenerator())->issue(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code('the-code', $client, $this->session, $issuedAt)),
            $issuedAt,
        )->value;
    }

    private static function basic(string $clientId, string $secret = Clients::SECRET): string
    {
        return 'Basic ' . base64_encode($clientId . ':' . $secret);
    }
}
