<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\EndSession;

use Heidi\Core\Application\Authentication\SessionTerminator;
use Heidi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Heidi\Core\Bridge\JwtFramework\JwtFrameworkJwsVerifier;
use Heidi\Core\Domain\Event\AuthenticationSessionEnded;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\EndSession\EndSessionHandler;
use Heidi\Oidc\Application\EndSession\EndSessionRequestParser;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Heidi\Oidc\Domain\Authorization\IdTokenHint;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\EndSession\EndSessionRequest;
use Heidi\Oidc\Domain\EndSession\LoggedOut;
use Heidi\Oidc\Domain\EndSession\LogoutConfirmationReason;
use Heidi\Oidc\Domain\EndSession\LogoutConfirmationRequired;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakePasswordHasher;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\Tokens;
use function http_build_query;
use function parse_str;
use const PHP_QUERY_RFC3986;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class EndSessionHandlerTest extends TestCase
{
    private Tenant $tenant;

    private User $alice;

    private Client $client;

    private AuthenticationSession $session;

    private RequestContext $context;

    private MockClock $clock;

    private InMemoryAuthenticationSessionRepository $sessions;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private RecordingEventDispatcher $events;

    private EndSessionHandler $handler;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->clock = new MockClock('2026-09-15T12:00:00+00:00');
        $this->context = Fixtures::context($this->clock->now(), '198.51.100.7');
        $this->session = Fixtures::session($this->alice, $this->clock->now()->modify('-1 hour'));
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->sessions->save($this->session);
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->events = new RecordingEventDispatcher();
        $this->handler = new EndSessionHandler(new SessionTerminator($this->sessions, $this->clock, $this->events), $this->refreshTokens, $this->clock);
    }

    /**
     * OIDC RP-Initiated Logout 1.0 §2 and architecture §4.9: a hint naming the user and the session the
     * browser holds is honoured without a question. The session ends by the relying party, once,
     * AuthenticationSessionEnded carries the request that ended it, every refresh token issued in the
     * session is revoked (decision 0006), those of other sessions are not, and the user agent goes
     * where the client asked with its state (§3).
     */
    #[Test]
    public function itEndsTheSessionTheHintDescribesWithoutAsking(): void
    {
        $issued = Fixtures::now();
        $family = Tokens::family($issued);
        $rotated = Tokens::refreshToken('rotated', $this->client, $this->session, $issued, $family);
        $rotated->rotate($issued->modify('+1 day'));
        $revoked = Tokens::refreshToken('revoked', $this->client, $this->session, $issued->modify('+1 day'), $family);
        $revoked->revoke($issued->modify('+2 days'));
        $current = Tokens::refreshToken('current', $this->client, $this->session, $issued->modify('+2 days'), $family);
        $otherSession = Fixtures::session($this->alice);
        $this->sessions->save($otherSession);
        $elsewhere = Tokens::refreshToken('elsewhere', $this->client, $otherSession, $issued);
        foreach ([$rotated, $revoked, $current, $elsewhere] as $token) {
            $this->refreshTokens->save($token);
        }
        $savesBefore = $this->refreshTokens->saves;
        $request = $this->request($this->hint($this->session), 'af0ifjsldkj');

        $decision = $this->handler->begin($request, $this->session, $this->context);

        static::assertInstanceOf(LoggedOut::class, $decision);
        static::assertSame($request, $decision->request);
        static::assertSame($this->session, $decision->endedSession);
        static::assertSame('https://demo.localhost/?state=af0ifjsldkj', $decision->redirect?->toUri());
        static::assertTrue($this->session->hasEnded());
        static::assertSame(SessionEnd::RelyingParty, $this->session->endedBy);
        static::assertEquals($this->clock->now(), $this->session->endedAt);
        static::assertSame([$otherSession], $this->sessions->findActiveByUser($this->alice, $this->clock->now()), 'the other session of the user is not touched');
        static::assertCount(1, $this->events->events);
        $event = $this->events->of(AuthenticationSessionEnded::class)[0];
        static::assertSame($this->session, $event->session);
        static::assertSame($this->context, $event->context);
        static::assertSame(SessionEnd::RelyingParty, $event->endedBy);
        static::assertTrue($rotated->isRevoked());
        static::assertEquals($this->clock->now(), $rotated->revokedAt);
        static::assertEquals($issued->modify('+2 days'), $revoked->revokedAt, 'the first revocation wins');
        static::assertTrue($current->isRevoked());
        static::assertFalse($elsewhere->isRevoked());
        static::assertSame($savesBefore + 2, $this->refreshTokens->saves, 'the two tokens revoked now are saved, the one already revoked is not');
    }

    /**
     * §2: the provider must ask when there is no id_token_hint, when the hint names another user, or
     * when it does not belong to the current session; §6: a request without a valid hint may be a
     * denial of service. Nothing is written until the user answers.
     *
     * @param callable(self): ?IdTokenHint $hint
     */
    #[Test]
    #[DataProvider('hintsThatDoNotProveTheSession')]
    public function itAsksBeforeEndingASessionTheHintDoesNotProve(callable $hint, LogoutConfirmationReason $reason): void
    {
        $token = Tokens::refreshToken('current', $this->client, $this->session, Fixtures::now());
        $this->refreshTokens->save($token);
        $savesBefore = $this->refreshTokens->saves + $this->sessions->saves;
        $request = $this->request($hint($this));

        $decision = $this->handler->begin($request, $this->session, $this->context);

        static::assertInstanceOf(LogoutConfirmationRequired::class, $decision);
        static::assertSame($request, $decision->request);
        static::assertSame($this->session, $decision->session);
        static::assertSame($reason, $decision->reason);
        static::assertTrue($this->session->isActive($this->clock->now()));
        static::assertFalse($token->isRevoked());
        static::assertSame($savesBefore, $this->refreshTokens->saves + $this->sessions->saves);
        static::assertSame([], $this->events->events);
    }

    /**
     * @return iterable<string, array{callable(self): ?IdTokenHint, LogoutConfirmationReason}>
     */
    public static function hintsThatDoNotProveTheSession(): iterable
    {
        yield 'no hint' => [
            static fn (self $test): ?IdTokenHint => null,
            LogoutConfirmationReason::NoHint,
        ];
        yield 'another user' => [
            static fn (self $test): IdTokenHint => new IdTokenHint(new Subject('bob-subject'), ['oidc-demo'], $test->session->id),
            LogoutConfirmationReason::DifferentUser,
        ];
        yield 'another session of the user' => [
            static fn (self $test): IdTokenHint => $test->hint(Fixtures::session($test->alice)),
            LogoutConfirmationReason::DifferentSession,
        ];
        yield 'no session in the hint' => [
            static fn (self $test): IdTokenHint => new IdTokenHint(new Subject('alice-subject'), ['oidc-demo'], null),
            LogoutConfirmationReason::DifferentSession,
        ];
    }

    /**
     * §2: "If the End-User says yes, then the OP MUST log out the End-User": after the confirmation
     * page, the session ends whatever the hint said, and the redirect is honoured.
     *
     * @param callable(self): ?IdTokenHint $hint
     */
    #[Test]
    #[DataProvider('hintsToConfirm')]
    public function itEndsTheSessionWhenTheUserConfirms(callable $hint): void
    {
        $token = Tokens::refreshToken('current', $this->client, $this->session, Fixtures::now());
        $this->refreshTokens->save($token);
        $request = $this->request($hint($this), 'af0ifjsldkj');

        $decision = $this->handler->confirm($request, $this->session, $this->context);

        static::assertSame($request, $decision->request);
        static::assertSame($this->session, $decision->endedSession);
        static::assertSame('https://demo.localhost/?state=af0ifjsldkj', $decision->redirect?->toUri());
        static::assertTrue($this->session->hasEnded());
        static::assertSame(SessionEnd::RelyingParty, $this->session->endedBy);
        static::assertTrue($token->isRevoked());
        static::assertCount(1, $this->events->of(AuthenticationSessionEnded::class));
    }

    /**
     * @return iterable<string, array{callable(self): ?IdTokenHint}>
     */
    public static function hintsToConfirm(): iterable
    {
        foreach (self::hintsThatDoNotProveTheSession() as $name => [$hint]) {
            yield $name => [$hint];
        }
    }

    /**
     * §4: a logout request is idempotent, it is not an error to log out a user who is not logged in.
     * No session, an ended one or an expired one: nothing to ask, nothing to end, no event, and the
     * user agent goes where the client asked when it may.
     *
     * @param callable(self): ?AuthenticationSession $session
     */
    #[Test]
    #[DataProvider('sessionsNotToEnd')]
    public function itConsidersTheUserLoggedOutWhenTheBrowserHoldsNoActiveSession(callable $session, bool $withHint): void
    {
        $token = Tokens::refreshToken('current', $this->client, $this->session, Fixtures::now());
        $this->refreshTokens->save($token);
        $request = $this->request($withHint ? $this->hint($this->session) : null);
        $held = $session($this);

        $begun = $this->handler->begin($request, $held, $this->context);
        $confirmed = $this->handler->confirm($request, $held, $this->context);

        foreach ([$begun, $confirmed] as $decision) {
            static::assertInstanceOf(LoggedOut::class, $decision);
            static::assertSame($request, $decision->request);
            static::assertNull($decision->endedSession);
            static::assertSame('https://demo.localhost/', $decision->redirect?->toUri());
        }
        static::assertFalse($token->isRevoked(), 'a token of the session the hint names is not revoked on the word of the token: the browser proves the session, the token does not');
        static::assertSame([], $this->events->events);
    }

    /**
     * @return iterable<string, array{callable(self): ?AuthenticationSession, bool}>
     */
    public static function sessionsNotToEnd(): iterable
    {
        yield 'no session, with a hint' => [
            static fn (self $test): ?AuthenticationSession => null,
            true,
        ];
        yield 'no session, without a hint' => [
            static fn (self $test): ?AuthenticationSession => null,
            false,
        ];
        yield 'session ended' => [static function (self $test): AuthenticationSession {
            $test->session->end(SessionEnd::User, $test->clock->now()->modify('-1 minute'));

            return $test->session;
        }, true];
        yield 'session expired' => [static function (self $test): AuthenticationSession {
            $test->clock->sleep(13 * 3600);

            return $test->session;
        }, true];
    }

    /**
     * A request that names no client, from a bare logout link: the session ends after confirmation
     * and there is nowhere to redirect to (§3).
     */
    #[Test]
    public function itRedirectsNowhereWhenTheRequestNamesNoClient(): void
    {
        $request = new EndSessionRequest($this->tenant, null, null, null);

        $begun = $this->handler->begin($request, $this->session, $this->context);
        static::assertInstanceOf(LogoutConfirmationRequired::class, $begun);
        static::assertSame(LogoutConfirmationReason::NoHint, $begun->reason);

        $confirmed = $this->handler->confirm($request, $this->session, $this->context);
        static::assertNull($confirmed->redirect);
        static::assertSame($this->session, $confirmed->endedSession);
        static::assertTrue($this->session->hasEnded());
    }

    /**
     * The session the integration hands over is one of the tenant the request reached; anything else is
     * a wiring error, not a decision.
     */
    #[Test]
    public function itRefusesASessionOfAnotherTenant(): void
    {
        $other = Fixtures::session(Fixtures::user(Fixtures::tenant('other', 'https://id.other.example')));
        $request = $this->request(null);

        try {
            $this->handler->begin($request, $other, $this->context);
            static::fail('The session should have been refused.');
        } catch (InvalidArgumentException) {
        }
        $this->expectException(InvalidArgumentException::class);
        $this->handler->confirm($request, $other, $this->context);
    }

    /**
     * The acceptance criterion of the issue, below HTTP: what OidcEndSessionListener of oidc_login 8.2
     * sends on logout is honoured without a question. The listener redirects the browser to the
     * end_session_endpoint with "id_token_hint", the last ID token it received, and
     * "post_logout_redirect_uri", the URI it generated, serialized with http_build_query in RFC 3986
     * encoding; no "state", no "client_id". The last ID token is often one re-issued on a refresh,
     * without "nonce", and may well be expired (§2: the provider should accept it): both are minted
     * here by the issuer of #8 and verified through the JWS bridge of the core, as the endpoint will.
     */
    #[Test]
    #[DataProvider('idTokensOidcLoginHolds')]
    public function itLogsOutWhatOidcLoginSends(bool $refreshed, int $secondsLater): void
    {
        $jwts = new Jwts($this->tenant);
        $issuer = new JwtIdTokenIssuer($jwts->signer, new PublicSubjectIdentifierResolver(), new StandardClaimsProvider());
        $accessToken = new AccessToken('jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y', Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $refreshToken = Tokens::refreshToken('current', $this->client, $this->session, Fixtures::now());
        $this->refreshTokens->save($refreshToken);
        $authorization = $refreshed
            ? GrantedAuthorization::fromRefreshToken($refreshToken, null)
            : GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now()));
        $idToken = $issuer->issue($authorization, $accessToken, Fixtures::now());
        $this->clock->sleep($secondsLater);
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);
        $parser = new EndSessionRequestParser($clients, new IdTokenHintVerifier(new JwtFrameworkJwsVerifier($jwts->keys)));
        $query = http_build_query([
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => 'https://demo.localhost/',
        ], '', '&', PHP_QUERY_RFC3986);

        $decision = $this->handler->begin($parser->parse($this->tenant, self::parameters($query)), $this->session, $this->context);

        static::assertInstanceOf(LoggedOut::class, $decision);
        static::assertSame($this->session, $decision->endedSession);
        static::assertSame('https://demo.localhost/', $decision->redirect?->toUri(), 'no state was sent, none comes back');
        static::assertTrue($this->session->hasEnded());
        static::assertTrue($refreshToken->isRevoked());
        static::assertCount(1, $this->events->of(AuthenticationSessionEnded::class));
    }

    /**
     * @return iterable<string, array{bool, int}>
     */
    public static function idTokensOidcLoginHolds(): iterable
    {
        yield 'from the code, still valid' => [false, 60];
        yield 'from a refresh, still valid' => [true, 60];
        yield 'from a refresh, expired an hour ago' => [true, 70 * 60];
    }

    /**
     * The query string as the integration will hand it over: parsed by PHP, names as strings.
     *
     * @return array<string, mixed>
     */
    private static function parameters(string $query): array
    {
        parse_str($query, $parsed);
        $parameters = [];
        foreach ($parsed as $name => $value) {
            $parameters[(string) $name] = $value;
        }

        return $parameters;
    }

    private function request(?IdTokenHint $hint, ?string $state = null): EndSessionRequest
    {
        return new EndSessionRequest($this->tenant, $this->client, $hint, $this->client->postLogoutRedirectUris[0], $state);
    }

    private function hint(AuthenticationSession $session): IdTokenHint
    {
        return new IdTokenHint($session->user->subject, ['oidc-demo'], $session->id);
    }
}
