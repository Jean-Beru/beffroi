<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Token\RefreshTokenGrant;
use Heidi\Oidc\Application\Token\TokenIssuer;
use Heidi\Oidc\Application\Token\TokenRequest;
use Heidi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Event\RefreshTokenReuseDetected;
use Heidi\Oidc\Domain\Event\RefreshTokenRotated;
use Heidi\Oidc\Domain\Event\TokensIssued;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Domain\Token\RefreshTokenFamily;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidGrantException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\InvalidScopeException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Heidi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Heidi\Oidc\Tests\Fixture\FakePasswordHasher;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class RefreshTokenGrantTest extends TestCase
{
    private Tenant $tenant;

    private User $alice;

    private Client $client;

    private AuthenticationSession $session;

    private RequestContext $context;

    private MockClock $clock;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private FakeIdTokenIssuer $idTokens;

    private RecordingEventDispatcher $events;

    private RefreshTokenGrant $grant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->clock = new MockClock('2026-09-15T12:00:00+00:00');
        $this->session = Fixtures::session($this->alice, $this->clock->now()->modify('-1 hour'));
        $this->context = Fixtures::context($this->clock->now());
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->idTokens = new FakeIdTokenIssuer();
        $this->events = new RecordingEventDispatcher();
        $issuer = new TokenIssuer(new FakeAccessTokenIssuer(), $this->idTokens, $this->refreshTokens, $this->events);
        $this->grant = new RefreshTokenGrant($this->refreshTokens, $issuer, $this->clock, $this->events);
    }

    #[Test]
    public function itHandlesTheRefreshTokenGrantType(): void
    {
        static::assertSame(GrantType::RefreshToken, $this->grant->grantType());
    }

    /**
     * RFC 6749 §6, RFC 9700 §4.13, OIDC Core §12.2: the token presented is rotated, its successor is
     * issued in the same family with the same scopes and a sliding expiry, the access token covers the
     * scopes of the token, and the ID token is reissued without nonce, with the original authentication.
     */
    #[Test]
    public function itRotatesTheTokenAndIssuesNewOnes(): void
    {
        $token = $this->token('the-token', ['openid', 'profile']);
        $this->clock->sleep(3600);

        $issued = $this->grant->grant($this->client, $this->request(), $this->context);

        static::assertTrue($token->isRotated());
        static::assertEquals($this->clock->now(), $token->rotatedAt);
        static::assertFalse($token->isRevoked());

        $successor = ($issued->refreshToken ?? static::fail('A refresh always issues a successor.'))->token;
        static::assertNotSame($token, $successor);
        static::assertNotSame($token->tokenHash, $successor->tokenHash);
        static::assertSame($token->family, $successor->family);
        static::assertSame($token->scopes, $successor->scopes);
        static::assertSame($this->client, $successor->client);
        static::assertSame($this->session, $successor->session);
        static::assertEquals($this->clock->now(), $successor->issuedAt);
        static::assertEquals($this->clock->now()->modify('+30 days'), $successor->expiresAt);
        static::assertEquals($token->authenticatedAt, $successor->authenticatedAt);
        static::assertFalse($successor->isRotated());
        static::assertSame([$token, $successor], $this->refreshTokens->all());
        static::assertSame(3, $this->refreshTokens->saves, 'the token in setUp, the rotation, the successor');

        static::assertSame(GrantType::RefreshToken, $issued->authorization->grantType);
        static::assertSame($token->scopes, $issued->authorization->scopes);
        static::assertNull($issued->authorization->nonce);
        static::assertEquals($token->authenticatedAt, $issued->authorization->authenticatedAt);
        static::assertSame('id:oidc-demo:alice-subject:-:' . $this->clock->now()->getTimestamp(), $issued->idToken);
        static::assertSame('openid profile', $issued->toResponse()->parameters()['scope']);

        static::assertCount(2, $this->events->events);
        $rotations = $this->events->of(RefreshTokenRotated::class);
        static::assertCount(1, $rotations);
        static::assertSame($token, $rotations[0]->previous);
        static::assertSame($successor, $rotations[0]->next);
        static::assertEquals($this->clock->now(), $rotations[0]->occurredAt);
        static::assertSame($this->tenant, $rotations[0]->tenant);
        static::assertSame($this->context, $rotations[0]->context);
        static::assertSame($successor, $this->events->of(TokensIssued::class)[0]->refreshToken);
    }

    /**
     * RFC 6749 §6: the scope asked for narrows this response, not the token: the successor keeps what
     * was granted. Below "openid", no ID token.
     */
    #[Test]
    public function itNarrowsTheScopeOfTheResponseButNotOfTheSuccessor(): void
    {
        $token = $this->token('the-token', ['openid', 'profile', 'email']);

        $issued = $this->grant->grant($this->client, $this->request(scope: 'email profile email'), $this->context);

        static::assertEquals([new Scope('email'), new Scope('profile')], $issued->authorization->scopes);
        static::assertSame($token->scopes, $issued->authorization->grantedScopes);
        static::assertNull($issued->idToken);
        static::assertSame([], $this->idTokens->issued);
        static::assertSame('email profile', $issued->toResponse()->parameters()['scope']);
        static::assertSame($token->scopes, ($issued->refreshToken ?? static::fail('A refresh always issues a successor.'))->token->scopes);

        $again = $this->grant->grant($this->client, $this->request($issued->refreshToken->value, 'openid'), $this->context);

        static::assertNotNull($again->idToken, 'what was granted can be asked for again');
    }

    /**
     * RFC 6749 §6: a scope not originally granted is "invalid_scope"; nothing is rotated.
     */
    #[Test]
    public function itRefusesAScopeOutsideTheGrant(): void
    {
        $token = $this->token('the-token', ['openid', 'profile']);

        try {
            $this->grant->grant($this->client, $this->request(scope: 'openid email'), $this->context);
            static::fail('The scope should have been refused.');
        } catch (InvalidScopeException $exception) {
            static::assertStringContainsString('exceeds', $exception->errorDescription);
        }
        static::assertFalse($token->isRotated());
        static::assertSame([], $this->events->events);
    }

    /**
     * RFC 6749 §3.3: a scope that is not a list of scope tokens is refused before anything is looked up.
     */
    #[Test]
    public function itRefusesAMalformedScope(): void
    {
        $token = $this->token('the-token');

        foreach (['openid  profile', 'open"id', ' openid'] as $scope) {
            try {
                $this->grant->grant($this->client, $this->request(scope: $scope), $this->context);
                static::fail('The scope should have been refused.');
            } catch (InvalidScopeException $exception) {
                static::assertStringContainsString('RFC 6749 section 3.3', $exception->errorDescription);
                static::assertInstanceOf(InvalidArgumentException::class, $exception->getPrevious());
            }
        }
        static::assertFalse($token->isRotated());
    }

    #[Test]
    public function itRequiresTheRefreshToken(): void
    {
        $this->token('the-token');

        try {
            $this->grant->grant($this->client, new TokenRequest([
                'grant_type' => 'refresh_token',
            ]), $this->context);
            static::fail('The refresh token is required.');
        } catch (InvalidRequestException $exception) {
            static::assertSame('The refresh_token parameter is missing.', $exception->errorDescription);
        }
    }

    /**
     * RFC 6749 §5.2: unknown, issued to another client, or revoked, it is "invalid_grant" with nothing
     * to tell one from the other, and nothing else happens: a token of another client is not a reuse,
     * even rotated, and a revoked one is not detected twice.
     */
    #[Test]
    public function itRefusesAnUnknownOrForeignOrRevokedToken(): void
    {
        $foreign = $this->token('foreign', client: Clients::public($this->tenant));
        $foreign->rotate($this->clock->now());
        $this->refreshTokens->save($foreign);
        $revoked = $this->token('revoked');
        $revoked->revoke($this->clock->now());
        $this->refreshTokens->save($revoked);

        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request('unknown'), $this->context));
        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request('foreign'), $this->context));
        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request('revoked'), $this->context));
        static::assertSame([], $this->events->events);
        static::assertSame(4, $this->refreshTokens->saves);
    }

    /**
     * RFC 9700 §4.13.2: a rotated token presented again reveals a copy; the whole family is revoked,
     * the presented token and the current one included, and the detection is announced once.
     */
    #[Test]
    public function itRevokesTheFamilyWhenARotatedTokenIsPresentedAgain(): void
    {
        $first = $this->token('first', ['openid', 'profile']);
        $other = $this->token('other', family: Tokens::family($this->clock->now(), 'other-code'));
        $this->clock->sleep(60);
        $second = $this->grant->grant($this->client, $this->request('first'), $this->context)
            ->refreshToken ?? static::fail('A refresh always issues a successor.');
        $this->clock->sleep(60);
        $third = $this->grant->grant($this->client, $this->request($second->value), $this->context)
            ->refreshToken ?? static::fail('A refresh always issues a successor.');
        $this->clock->sleep(60);

        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request('first'), $this->context));

        foreach ([$first, $second->token, $third->token] as $token) {
            static::assertTrue($token->isRevoked());
            static::assertEquals($this->clock->now(), $token->revokedAt);
        }
        static::assertFalse($other->isRevoked(), 'another family is not concerned');
        static::assertSame(9, $this->refreshTokens->saves, 'two fixtures, two rotations with their successors, three revocations');
        $detections = $this->events->of(RefreshTokenReuseDetected::class);
        static::assertCount(1, $detections);
        static::assertSame($first, $detections[0]->presented);
        static::assertSame([$first, $second->token, $third->token], $detections[0]->revoked);
        static::assertEquals($this->clock->now(), $detections[0]->occurredAt);
        static::assertSame($this->tenant, $detections[0]->tenant);
        static::assertSame($this->context, $detections[0]->context);
        static::assertCount(2, $this->events->of(TokensIssued::class));

        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request($third->value), $this->context));
        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request($second->value), $this->context));

        static::assertCount(1, $this->events->of(RefreshTokenReuseDetected::class), 'a revoked family is not detected again');
    }

    /**
     * Architecture §4.6: thirty days sliding, ninety days absolute; the last instant excluded.
     */
    #[Test]
    public function itRefusesAnExpiredToken(): void
    {
        $this->token('sliding');
        $family = Tokens::family($this->clock->now()->modify('-89 days'), 'old-code');
        $this->token('absolute', family: $family);
        $this->clock->sleep(30 * 86400 - 1);

        $successor = $this->grant->grant($this->client, $this->request('sliding'), $this->context)
            ->refreshToken ?? static::fail('A refresh always issues a successor.');
        static::assertEquals($this->clock->now()->modify('+30 days'), $successor->token->expiresAt);
        $this->clock->sleep(1);
        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request('absolute'), $this->context), 'the family expired one day after this token was issued');
        $this->clock->sleep(30 * 86400);
        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request($successor->value), $this->context));
        static::assertSame([], $this->events->of(RefreshTokenReuseDetected::class));
    }

    /**
     * Architecture §4.9: a logout revokes the tokens of the session; one that outlived the revocation
     * is refused rather than honoured. An expired session is another matter: offline access is what a
     * refresh token is for.
     */
    #[Test]
    public function itRefusesATokenWhoseSessionHasEndedButNotOneWhoseSessionExpired(): void
    {
        $ended = Fixtures::session($this->alice, $this->clock->now()->modify('-1 hour'));
        $this->token('ended', session: $ended);
        $ended->end(SessionEnd::User, $this->clock->now());
        $this->token('expired', session: Fixtures::session($this->alice, $this->clock->now()->modify('-2 days')));

        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request('ended'), $this->context));
        static::assertNotNull($this->grant->grant($this->client, $this->request('expired'), $this->context)->idToken);
    }

    /**
     * @param list<string> $scopes
     */
    private function token(string $value, array $scopes = ['openid'], ?Client $client = null, ?RefreshTokenFamily $family = null, ?AuthenticationSession $session = null): RefreshToken
    {
        $token = Tokens::refreshToken($value, $client ?? $this->client, $session ?? $this->session, $this->clock->now(), $family, $scopes);
        $this->refreshTokens->save($token);

        return $token;
    }

    private function request(string $refreshToken = 'the-token', ?string $scope = null): TokenRequest
    {
        $parameters = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
        ];
        if ($scope !== null) {
            $parameters['scope'] = $scope;
        }

        return new TokenRequest($parameters);
    }

    /**
     * @param callable(): IssuedTokens $attempt
     */
    private function assertInvalidGrant(callable $attempt, string $message = ''): void
    {
        try {
            $attempt();
            static::fail($message !== '' ? $message : 'The grant should have failed.');
        } catch (InvalidGrantException $exception) {
            static::assertSame('The refresh token is invalid.', $exception->errorDescription);
            static::assertSame(400, $exception->statusCode);
        }
    }
}
