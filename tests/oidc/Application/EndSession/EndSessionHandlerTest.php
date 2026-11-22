<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\EndSession;

use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Beffroi\Oidc\Application\Claims\AssignedSubjectIdentifiers;
use Beffroi\Oidc\Application\Claims\StandardClaimsProvider;
use Beffroi\Oidc\Application\EndSession\EndSessionHandler;
use Beffroi\Oidc\Application\EndSession\EndSessionRequestParser;
use Beffroi\Oidc\Application\Token\JwtIdTokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Authorization\IdTokenHint;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\EndSession\EndSessionRequest;
use Beffroi\Oidc\Domain\EndSession\LoggedOut;
use Beffroi\Oidc\Domain\EndSession\LogoutConfirmationReason;
use Beffroi\Oidc\Domain\EndSession\LogoutConfirmationRequired;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use function http_build_query;
use function parse_str;
use const PHP_QUERY_RFC3986;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Beffroi\Oidc\Tests\Fixture\Subjects;
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

    private RecordingEventDispatcher $events;

    private AssignedSubjectIdentifiers $subjects;

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
        $this->events = new RecordingEventDispatcher();
        $users = new InMemoryUserRepository();
        $users->save($this->alice);
        $users->save(Fixtures::user($this->tenant, 'bob', 'bob-subject'));
        $this->subjects = Subjects::bothKinds($users);
        $this->handler = new EndSessionHandler(
            new SessionTerminator($this->sessions, $this->clock, $this->events),
            $this->subjects,
            $this->clock,
        );
    }

    /**
     * OIDC RP-Initiated Logout 1.0 §2, §3, Architecture §4.9
     */
    #[Test]
    public function itEndsTheSessionTheHintDescribesWithoutAsking(): void
    {
        // Given
        $request = $this->request($this->hint($this->session), 'af0ifjsldkj');

        // When
        $decision = $this->handler->begin($request, $this->session, $this->context);

        // Then
        static::assertInstanceOf(LoggedOut::class, $decision);
        static::assertSame($request, $decision->request);
        static::assertSame($this->session, $decision->endedSession);
        static::assertSame('https://demo.localhost/?state=af0ifjsldkj', $decision->redirect?->toUri());
    }

    #[Test]
    public function theSessionEndsByTheRelyingParty(): void
    {
        // When
        $this->handler->begin($this->request($this->hint($this->session)), $this->session, $this->context);

        // Then
        static::assertTrue($this->session->hasEnded());
        static::assertSame(SessionEnd::RelyingParty, $this->session->endedBy);
        static::assertEquals($this->clock->now(), $this->session->endedAt);
    }

    #[Test]
    public function theOtherSessionsOfTheUserAreNotTouched(): void
    {
        // Given
        $otherSession = Fixtures::session($this->alice);
        $this->sessions->save($otherSession);

        // When
        $this->handler->begin($this->request($this->hint($this->session)), $this->session, $this->context);

        // Then
        static::assertSame([$otherSession], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
    }

    #[Test]
    public function theEndOfTheSessionIsAnnouncedOnceWithTheRequestContext(): void
    {
        // When
        $this->handler->begin($this->request($this->hint($this->session)), $this->session, $this->context);

        // Then
        static::assertCount(1, $this->events->events);
        $event = $this->events->of(AuthenticationSessionEnded::class)[0];
        static::assertSame($this->session, $event->session);
        static::assertSame($this->context, $event->context);
        static::assertSame(SessionEnd::RelyingParty, $event->endedBy);
    }

    /**
     * OIDC RP-Initiated Logout 1.0 §2, §6
     *
     * @param callable(self): ?IdTokenHint $hint
     */
    #[Test]
    #[DataProvider('provideHintsThatDoNotProveTheSession')]
    public function itAsksBeforeEndingASessionTheHintDoesNotProve(callable $hint, LogoutConfirmationReason $reason): void
    {
        // Given
        $request = $this->request($hint($this));

        // When
        $decision = $this->handler->begin($request, $this->session, $this->context);

        // Then
        static::assertInstanceOf(LogoutConfirmationRequired::class, $decision);
        static::assertSame($request, $decision->request);
        static::assertSame($this->session, $decision->session);
        static::assertSame($reason, $decision->reason);
    }

    /**
     * @param callable(self): ?IdTokenHint $hint
     */
    #[Test]
    #[DataProvider('provideHintsThatDoNotProveTheSession')]
    public function nothingIsWrittenUntilTheUserAnswers(callable $hint, LogoutConfirmationReason $reason): void
    {
        // Given
        $savesBefore = $this->sessions->saves;

        // When
        $this->handler->begin($this->request($hint($this)), $this->session, $this->context);

        // Then
        static::assertTrue($this->session->isActive($this->clock->now()));
        static::assertSame($savesBefore, $this->sessions->saves);
        static::assertSame([], $this->events->events);
    }

    /**
     * @return iterable<string, array{callable(self): ?IdTokenHint, LogoutConfirmationReason}>
     */
    public static function provideHintsThatDoNotProveTheSession(): iterable
    {
        yield 'no hint' => [
            static fn (self $test): ?IdTokenHint => null,
            LogoutConfirmationReason::NoHint,
        ];
        yield 'another user' => [
            static fn (self $test): IdTokenHint => new IdTokenHint(new Subject('bob-subject'), ['oidc-demo'], $test->session->id),
            LogoutConfirmationReason::DifferentUser,
        ];
        yield 'a subject that names nobody' => [
            static fn (self $test): IdTokenHint => new IdTokenHint(new Subject('nobody-subject'), ['oidc-demo'], $test->session->id),
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
     * OIDC Core §8.1, RP-Initiated Logout §2
     */
    #[Test]
    public function aHintOfAPairwiseClientNamingTheSessionEndsItWithoutAsking(): void
    {
        // Given
        $client = Clients::pairwise($this->tenant);
        $hint = new IdTokenHint($this->subjects->resolve($this->alice, $client), ['pairwise-app'], $this->session->id);

        // When
        $decision = $this->handler->begin(new EndSessionRequest($this->tenant, $client, $hint, null), $this->session, $this->context);

        // Then
        static::assertInstanceOf(LoggedOut::class, $decision);
        static::assertSame($this->session, $decision->endedSession);
    }

    /**
     * OIDC Core §8
     */
    #[Test]
    public function theSubjectTheCoreKeepsNamesNobodyToAPairwiseClient(): void
    {
        // Given
        $client = Clients::pairwise($this->tenant);
        $hint = new IdTokenHint($this->alice->subject, ['pairwise-app'], $this->session->id);

        // When
        $decision = $this->handler->begin(new EndSessionRequest($this->tenant, $client, $hint, null), $this->session, $this->context);

        // Then
        static::assertInstanceOf(LogoutConfirmationRequired::class, $decision);
        static::assertSame(LogoutConfirmationReason::DifferentUser, $decision->reason);
    }

    /**
     * OIDC RP-Initiated Logout 1.0 §2, §6
     */
    #[Test]
    public function itAsksWhenTheHintCouldNotBeVerified(): void
    {
        // Given
        $request = new EndSessionRequest($this->tenant, null, null, null, invalidIdTokenHint: true);

        // When
        $decision = $this->handler->begin($request, $this->session, $this->context);

        // Then
        static::assertInstanceOf(LogoutConfirmationRequired::class, $decision);
        static::assertSame(LogoutConfirmationReason::InvalidHint, $decision->reason);
    }

    /**
     * OIDC RP-Initiated Logout 1.0 §2
     */
    #[Test]
    public function itEndsTheSessionWhenTheUserConfirmsDespiteAnInvalidHint(): void
    {
        // Given
        $request = new EndSessionRequest($this->tenant, null, null, null, invalidIdTokenHint: true);

        // When
        $decision = $this->handler->confirm($request, $this->session, $this->context);

        // Then
        static::assertSame($this->session, $decision->endedSession);
        static::assertNull($decision->redirect);
        static::assertTrue($this->session->hasEnded());
    }

    /**
     * OIDC RP-Initiated Logout 1.0 §2
     *
     * @param callable(self): ?IdTokenHint $hint
     */
    #[Test]
    #[DataProvider('provideHintsToConfirm')]
    public function itEndsTheSessionWhenTheUserConfirms(callable $hint): void
    {
        // Given
        $request = $this->request($hint($this), 'af0ifjsldkj');

        // When
        $decision = $this->handler->confirm($request, $this->session, $this->context);

        // Then
        static::assertSame($request, $decision->request);
        static::assertSame($this->session, $decision->endedSession);
        static::assertSame('https://demo.localhost/?state=af0ifjsldkj', $decision->redirect?->toUri());
        static::assertTrue($this->session->hasEnded());
        static::assertSame(SessionEnd::RelyingParty, $this->session->endedBy);
    }

    /**
     * @param callable(self): ?IdTokenHint $hint
     */
    #[Test]
    #[DataProvider('provideHintsToConfirm')]
    public function aConfirmedLogoutAnnouncesTheEnd(callable $hint): void
    {
        // When
        $this->handler->confirm($this->request($hint($this)), $this->session, $this->context);

        // Then
        static::assertCount(1, $this->events->of(AuthenticationSessionEnded::class));
    }

    /**
     * @return iterable<string, array{callable(self): ?IdTokenHint}>
     */
    public static function provideHintsToConfirm(): iterable
    {
        foreach (self::provideHintsThatDoNotProveTheSession() as $name => [$hint]) {
            yield $name => [$hint];
        }
    }

    /**
     * OIDC RP-Initiated Logout 1.0 §4
     *
     * @param callable(self): ?AuthenticationSession $session
     */
    #[Test]
    #[DataProvider('provideSessionsNotToEnd')]
    public function itConsidersTheUserLoggedOutWhenTheBrowserHoldsNoActiveSession(callable $session, bool $withHint): void
    {
        // Given
        $request = $this->request($withHint ? $this->hint($this->session) : null);
        $held = $session($this);

        // When
        $decision = $this->handler->begin($request, $held, $this->context);

        // Then
        static::assertInstanceOf(LoggedOut::class, $decision);
        static::assertSame($request, $decision->request);
        static::assertNull($decision->endedSession);
        static::assertSame('https://demo.localhost/', $decision->redirect?->toUri());
    }

    /**
     * @param callable(self): ?AuthenticationSession $session
     */
    #[Test]
    #[DataProvider('provideSessionsNotToEnd')]
    public function aConfirmationWithoutAnActiveSessionEndsNothingEither(callable $session, bool $withHint): void
    {
        // Given
        $request = $this->request($withHint ? $this->hint($this->session) : null);
        $held = $session($this);

        // When
        $decision = $this->handler->confirm($request, $held, $this->context);

        // Then
        static::assertSame($request, $decision->request);
        static::assertNull($decision->endedSession);
        static::assertSame('https://demo.localhost/', $decision->redirect?->toUri());
    }

    /**
     * @param callable(self): ?AuthenticationSession $session
     */
    #[Test]
    #[DataProvider('provideSessionsNotToEnd')]
    public function nothingIsAnnouncedWithoutAnActiveSession(callable $session, bool $withHint): void
    {
        // Given
        $request = $this->request($withHint ? $this->hint($this->session) : null);
        $held = $session($this);

        // When
        $this->handler->begin($request, $held, $this->context);
        $this->handler->confirm($request, $held, $this->context);

        // Then
        static::assertSame([], $this->events->events);
    }

    /**
     * @return iterable<string, array{callable(self): ?AuthenticationSession, bool}>
     */
    public static function provideSessionsNotToEnd(): iterable
    {
        yield 'no session, with a hint' => [
            static fn (self $test): ?AuthenticationSession => null,
            true,
        ];
        yield 'no session, without a hint' => [
            static fn (self $test): ?AuthenticationSession => null,
            false,
        ];
        yield 'session ended' => [
            static function (self $test): AuthenticationSession {
                $test->session->end(SessionEnd::User, $test->clock->now()->modify('-1 minute'));

                return $test->session;
            },
            true,
        ];
        yield 'session expired' => [
            static function (self $test): AuthenticationSession {
                $test->clock->sleep(13 * 3600);

                return $test->session;
            },
            true,
        ];
    }

    #[Test]
    public function itAsksWhenTheRequestNamesNoClient(): void
    {
        // Given
        $request = new EndSessionRequest($this->tenant, null, null, null);

        // When
        $decision = $this->handler->begin($request, $this->session, $this->context);

        // Then
        static::assertInstanceOf(LogoutConfirmationRequired::class, $decision);
        static::assertSame(LogoutConfirmationReason::NoHint, $decision->reason);
    }

    /**
     * OIDC RP-Initiated Logout 1.0 §3
     */
    #[Test]
    public function itRedirectsNowhereWhenTheRequestNamesNoClient(): void
    {
        // Given
        $request = new EndSessionRequest($this->tenant, null, null, null);

        // When
        $decision = $this->handler->confirm($request, $this->session, $this->context);

        // Then
        static::assertNull($decision->redirect);
        static::assertSame($this->session, $decision->endedSession);
        static::assertTrue($this->session->hasEnded());
    }

    #[Test]
    public function beginRefusesASessionOfAnotherTenant(): void
    {
        // Given
        $other = Fixtures::session(Fixtures::user(Fixtures::tenant('other', 'https://id.other.example')));

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->handler->begin($this->request(null), $other, $this->context);
    }

    #[Test]
    public function confirmRefusesASessionOfAnotherTenant(): void
    {
        // Given
        $other = Fixtures::session(Fixtures::user(Fixtures::tenant('other', 'https://id.other.example')));

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->handler->confirm($this->request(null), $other, $this->context);
    }

    /**
     * OIDC RP-Initiated Logout 1.0 §2
     */
    #[Test]
    #[DataProvider('provideIdTokensOidcLoginHolds')]
    public function itLogsOutWhatOidcLoginSends(bool $refreshed, int $secondsLater): void
    {
        // Given
        $jwts = new Jwts($this->tenant);
        $issuer = new JwtIdTokenIssuer($jwts->documents, Subjects::publicKind(), new StandardClaimsProvider(), Algorithms::all());
        $accessToken = new AccessToken('jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y', Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $refreshToken = Tokens::refreshToken('current', $this->client, $this->session, Fixtures::now());
        $authorization = $refreshed
            ? UserAuthorization::fromRefreshToken(Grants::refreshToken(), $refreshToken, null)
            : UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
                'the-code',
                $this->client,
                $this->session,
                Fixtures::now(),
            ));
        $idToken = $issuer->issue($authorization, $accessToken, $issuer->address($authorization->client), Fixtures::now());
        $this->clock->sleep($secondsLater);
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);
        $parser = new EndSessionRequestParser($clients, new IdTokenHintVerifier(new JwtLibraryJwsVerifier($jwts->keys, Algorithms::all())));
        $query = http_build_query(
            [
                'id_token_hint' => $idToken,
                'post_logout_redirect_uri' => 'https://demo.localhost/',
            ],
            '',
            '&',
            PHP_QUERY_RFC3986,
        );

        // When
        $decision = $this->handler->begin($parser->parse($this->tenant, self::parameters($query)), $this->session, $this->context);

        // Then
        static::assertInstanceOf(LoggedOut::class, $decision);
        static::assertSame($this->session, $decision->endedSession);
        static::assertSame('https://demo.localhost/', $decision->redirect?->toUri(), 'no state was sent, none comes back');
        static::assertTrue($this->session->hasEnded());
        static::assertCount(1, $this->events->of(AuthenticationSessionEnded::class));
    }

    /**
     * @return iterable<string, array{bool, int}>
     */
    public static function provideIdTokensOidcLoginHolds(): iterable
    {
        yield 'from the code, still valid' => [false, 60];
        yield 'from a refresh, still valid' => [true, 60];
        yield 'from a refresh, expired an hour ago' => [true, 70 * 60];
    }

    /**
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
        return new EndSessionRequest($this->tenant, $this->client, $hint, $this->client->registration->postLogoutRedirectUris[0], $state);
    }

    private function hint(AuthenticationSession $session): IdTokenHint
    {
        return new IdTokenHint($session->user->subject, ['oidc-demo'], $session->id);
    }
}
