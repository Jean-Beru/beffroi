<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Token\AccessTokenInspector;
use Beffroi\Oidc\Tests\Fixture\AccessTokenShapes;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Application\Token\SealedPerson;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Token\ClientAuthorization;
use Beffroi\Oidc\Domain\Token\SubjectAuthorization;
use Beffroi\Oidc\Domain\Token\TokenSignIn;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Exception\InvalidTokenException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use Beffroi\Oidc\Tests\Fixture\Shapes;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use Symfony\Component\Uid\Uuid;

/**
 * The checks the provider's own resources add to the verification (architecture §4.6): the session, the
 * grant and the user, asked in one way of both shapes of token, an opaque one being the shape used
 * wherever the shape is not what the test is about.
 */
final class AccessTokenInspectorTest extends TestCase
{
    /**
     * The "sub" of the token a gateway presents at an exchange: a name the client that token was written
     * for holds, which no kind of this provider resolves for anybody else (OIDC Core §8.1).
     */
    private const string SUBJECT_OF_THE_FIRST_CLIENT = 'alice-to-the-first-client';

    private Tenant $tenant;

    private User $user;

    private Client $client;

    private AuthenticationSession $session;

    private InMemoryAuthorizationCodeRepository $grants;

    private InMemoryAccessTokenRepository $tokens;

    private InMemoryAuthenticationSessionRepository $sessions;

    private Jwts $jwts;

    private InMemoryClientRepository $clients;

    private SealedPerson $persons;

    private AccessTokenInspector $inspector;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->user = Fixtures::user($this->tenant);
        $this->client = Clients::public($this->tenant);
        $this->session = Fixtures::session($this->user);
        $this->grants = new InMemoryAuthorizationCodeRepository();
        $this->tokens = new InMemoryAccessTokenRepository();
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->sessions->save($this->session);
        $this->jwts = new Jwts($this->tenant);
        $users = new InMemoryUserRepository();
        $users->save($this->user);
        $this->clients = new InMemoryClientRepository();
        $this->clients->save($this->client);
        $this->persons = Subjects::sealedPerson();
        $this->inspector = new AccessTokenInspector(
            AccessTokenShapes::verifier(
                new JwtLibraryJwsVerifier($this->jwts->keys, Algorithms::all()),
                $this->clients,
                $this->tokens,
                Subjects::publicKind(),
                $this->persons,
            ),
            $this->sessions,
            $this->grants,
            Subjects::personOfAToken($users),
        );
    }

    /**
     * The person is answered for in one way whatever shape the token took (issue #601): the record of an
     * opaque token names them, an "at+jwt" carries a "sub" read for the client it was written for, and the
     * resource that asked is handed the same user.
     */
    #[Test]
    #[DataProvider('provideAccessTokenShapes')]
    public function itHandsOverTheVerifiedTokenAndItsUser(string $shape): void
    {
        // Given
        $token = $this->tokenOfShape($shape, $this->code());

        // When
        $inspected = $this->inspector->inspect($this->tenant, $token, Fixtures::now());

        // Then
        static::assertSame($this->user, $inspected->user);
        static::assertSame($this->client, $inspected->token->client);
        static::assertSame('alice-subject', (string) $inspected->token->subject);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAccessTokenShapes(): iterable
    {
        yield 'opaque' => ['opaque'];
        yield 'at+jwt' => ['jwt'];
    }

    /**
     * RFC 8693 §2.2.1, OIDC Core §8.1 and issue #601: the record of an exchanged token keeps the "sub" the
     * presented token carried, a name only the client that token was written for holds, and the person the
     * exchange resolved when it read it. The person is read off that record, so the token names a user
     * under a kind that could never have resolved that "sub" for the client holding it.
     */
    #[Test]
    public function itNamesThePersonTheRecordOfAnExchangedTokenKeeps(): void
    {
        // Given
        $token = $this->exchangedToken($this->code(), $this->user->subject);

        // When
        $inspected = $this->inspector->inspect($this->tenant, $token, Fixtures::now());

        // Then
        static::assertSame($this->user, $inspected->user);
        static::assertSame(self::SUBJECT_OF_THE_FIRST_CLIENT, (string) $inspected->token->subject);
    }

    /**
     * Issue #641: the self-contained shape keeps no record, so what the exchange resolved travels in the
     * token, sealed, and the resource that asked is handed the same person the record of the opaque shape
     * names. Read under the client that asked, that "sub" would name nobody (OIDC Core §8.1).
     */
    #[Test]
    public function itNamesThePersonASelfContainedExchangedTokenCarries(): void
    {
        // Given
        $token = $this->selfContainedExchangedToken($this->code(), $this->user->subject);

        // When
        $inspected = $this->inspector->inspect($this->tenant, $token, Fixtures::now());

        // Then
        static::assertSame($this->user, $inspected->user);
        static::assertSame(self::SUBJECT_OF_THE_FIRST_CLIENT, (string) $inspected->token->subject);
    }

    /**
     * A person the provider no longer serves is refused whichever name the token holds them under: the
     * record names them and the account is read by that name, so a disabled person is refused there as
     * anywhere else.
     */
    #[Test]
    public function itRefusesAnExchangedTokenOfADisabledPerson(): void
    {
        // Given
        $token = $this->exchangedToken($this->code(), $this->user->subject);
        $this->user->disable(Fixtures::now());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token names a user this provider no longer serves.');

        // When
        $this->inspector->inspect($this->tenant, $token, Fixtures::now());
    }

    /**
     * RFC 6749 §4.4: a token a client holds for itself descends from no session and names nobody, so
     * neither question is asked of it; it is honoured on what it carries, and the resource that answers
     * for a user is told there is none.
     */
    #[Test]
    public function itHandsOverATokenNobodySignedInForWithoutAUser(): void
    {
        // Given
        $token = $this->clientToken();

        // When
        $inspected = $this->inspector->inspect($this->tenant, $token, Fixtures::now());

        // Then
        static::assertNull($inspected->user);
        static::assertNull($inspected->token->signIn);
        static::assertSame('batch', (string) $inspected->token->subject);
    }

    /**
     * The session of the tokens of a user having ended says nothing about a token nobody signed in for: it
     * has no session to have ended and no grant of a browser flow to be revoked with one.
     */
    #[Test]
    public function aTokenNobodySignedInForOutlivesTheLogoutOfEverybody(): void
    {
        // Given
        $token = $this->clientToken();
        $this->session->end(SessionEnd::User, Fixtures::now()->modify('+1 minute'));

        // When
        $inspected = $this->inspector->inspect($this->tenant, $token, Fixtures::now());

        // Then
        static::assertNull($inspected->user);
    }

    /**
     * Issue #831, RFC 7523 §2.1: a token issued on the assertion of an issuer the tenant trusts descends from
     * no sign-in of this provider and still says who it is about, in either shape, so the resource that asked
     * is handed that person as it is for a token somebody signed in for.
     */
    #[Test]
    #[DataProvider('provideAccessTokenShapes')]
    public function itNamesThePersonOfATokenNobodySignedInFor(string $shape): void
    {
        // Given
        $token = $this->tokenOfAnAssertion($shape);

        // When
        $inspected = $this->inspector->inspect($this->tenant, $token, Fixtures::now());

        // Then
        static::assertSame($this->user, $inspected->user);
        static::assertNull($inspected->token->signIn);
    }

    /**
     * Issue #831: a token that descends from no sign-in has no session to have ended, and its person is asked
     * all the same. A person the provider no longer serves is refused whichever way a token came to name
     * them.
     */
    #[Test]
    #[DataProvider('provideAccessTokenShapes')]
    public function itRefusesATokenNobodySignedInForOfADisabledPerson(string $shape): void
    {
        // Given
        $token = $this->tokenOfAnAssertion($shape);
        $this->user->disable(Fixtures::now());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token names a user this provider no longer serves.');

        // When
        $this->inspector->inspect($this->tenant, $token, Fixtures::now());
    }

    /**
     * RFC 6749 §4.1.2: the replay of the code revoked the grant; every token descending from it is refused.
     */
    #[Test]
    public function itRefusesATokenOfARevokedGrant(): void
    {
        // Given
        $code = $this->code();
        $token = $this->tokenOf($code);
        $code->revoke(Fixtures::now());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a grant this provider revoked.');

        // When
        $this->inspector->inspect($this->tenant, $token, Fixtures::now());
    }

    /**
     * A grant the provider no longer keeps is a grant it cannot vouch for.
     */
    #[Test]
    public function itRefusesATokenWhoseGrantIsGone(): void
    {
        // Given
        $token = $this->tokenOf(Tokens::code('the-code', $this->client, $this->session, Fixtures::now()));

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a grant this provider revoked.');

        // When
        $this->inspector->inspect($this->tenant, $token, Fixtures::now());
    }

    #[Test]
    public function itRefusesATokenOfADisabledUser(): void
    {
        // Given
        $token = $this->tokenOf($this->code());
        $this->user->disable(Fixtures::now());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token names a user this provider no longer serves.');

        // When
        $this->inspector->inspect($this->tenant, $token, Fixtures::now());
    }

    #[Test]
    public function itRefusesATokenOfAUserGone(): void
    {
        // Given
        $inspector = new AccessTokenInspector(
            AccessTokenShapes::verifier(
                new JwtLibraryJwsVerifier($this->jwts->keys, Algorithms::all()),
                new InMemoryClientRepository(),
                $this->tokens,
                Subjects::publicKind(),
            ),
            $this->sessions,
            $this->grants,
            Subjects::personOfAToken(new InMemoryUserRepository()),
        );
        $token = $this->tokenOf($this->code());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token names a user this provider no longer serves.');

        // When
        $inspector->inspect($this->tenant, $token, Fixtures::now());
    }

    /**
     * What the verifier refuses, the inspector refuses, before any grant or user is looked at.
     */
    #[Test]
    public function itRefusesWhatTheVerifierRefuses(): void
    {
        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token is not an access token issued by this provider.');

        // When
        $this->inspector->inspect($this->tenant, 'unknown', Fixtures::now());
    }

    /**
     * Architecture §4.9 and issue #150: what a logout ends, it ends for both shapes of token. An opaque
     * one is refused by the record the provider keeps, an "at+jwt" by the "sid" it carries, and the
     * question is asked in the same place for both.
     */
    #[Test]
    #[DataProvider('provideAccessTokenShapes')]
    public function itRefusesATokenOfASessionThatEnded(string $shape): void
    {
        // Given
        $token = $this->tokenOfShape($shape, $this->code());
        $this->session->end(SessionEnd::User, Fixtures::now()->modify('+1 minute'));

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a session this provider ended.');

        // When
        $this->inspector->inspect($this->tenant, $token, Fixtures::now()->modify('+2 minutes'));
    }

    /**
     * Decision 0031: reaching its expiry does not end a session, so a token issued under it in its last
     * minute is honoured, in both shapes, until its own expiry.
     */
    #[Test]
    #[DataProvider('provideAccessTokenShapes')]
    public function itHonoursATokenOfASessionPastItsExpiry(string $shape): void
    {
        // Given
        $expiring = Fixtures::session($this->user, Fixtures::now()->modify('-12 hours +1 minute'));
        $this->sessions->save($expiring);
        $code = Tokens::code('the-code', $this->client, $expiring, Fixtures::now());
        $this->grants->save($code);
        $token = $this->tokenOfShape($shape, $code);

        // When
        $inspected = $this->inspector->inspect($this->tenant, $token, Fixtures::now()->modify('+2 minutes'));

        // Then
        static::assertSame($this->user, $inspected->user);
    }

    /**
     * A session the provider no longer keeps is a session it cannot vouch for, as a grant it no longer
     * keeps is.
     */
    #[Test]
    public function itRefusesATokenWhoseSessionIsGone(): void
    {
        // Given
        $token = $this->tokenOfShape('jwt', $this->code());
        $sessions = new InMemoryAuthenticationSessionRepository();
        $users = new InMemoryUserRepository();
        $users->save($this->user);
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);
        $inspector = new AccessTokenInspector(
            AccessTokenShapes::verifier(
                new JwtLibraryJwsVerifier($this->jwts->keys, Algorithms::all()),
                $clients,
                $this->tokens,
                Subjects::publicKind(),
            ),
            $sessions,
            $this->grants,
            Subjects::personOfAToken($users),
        );

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a session this provider ended.');

        // When
        $inspector->inspect($this->tenant, $token, Fixtures::now());
    }

    /**
     * An opaque token a client holds for itself (RFC 6749 §4.4), of a service client the repository knows.
     */
    private function clientToken(): string
    {
        $service = Clients::service($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->clients->save($service);

        return Tokens::accessToken(
            $this->opaque(),
            new ClientAuthorization(
                Grants::clientCredentials(),
                Uuid::v7(),
                $service,
                new Scopes([new Scope('invoices.read')]),
                ResourceIndicators::of([Clients::CALENDAR]),
            ),
            Fixtures::now(),
        )->value;
    }

    /**
     * RFC 8693 §2.1: the record of a token a gateway was given for the subject of the token it presented,
     * descending from the same grant and the same sign-in, with the person the exchange resolved then.
     */
    private function exchangedToken(AuthorizationCode $code, Subject $person): string
    {
        $gateway = Clients::gateway(
            $this->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            'person-gateway',
            accessTokenShape: Shapes::opaque(),
        );
        $this->clients->save($gateway);
        $value = Secrets::draw();
        $this->tokens->save(Tokens::storedSubjectAccessToken(
            $value,
            $gateway,
            new Subject(self::SUBJECT_OF_THE_FIRST_CLIENT),
            Fixtures::now(),
            grantId: $code->grantId,
            session: $this->session,
            person: $person,
        ));

        return $value;
    }

    /**
     * RFC 8693 §2.1: the same exchange in the self-contained shape, where the person the exchange resolved
     * is a claim of the token and not a column of a row (issue #641).
     */
    private function selfContainedExchangedToken(AuthorizationCode $code, Subject $person): string
    {
        $gateway = Clients::gateway($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), 'person-jwt-gateway');
        $this->clients->save($gateway);

        return Tokens::accessToken(
            new JwtAccessTokenIssuer(
                $this->jwts->signer,
                Subjects::publicKind(),
                Algorithms::all(),
                new SymfonyUuidGenerator(),
                $this->persons,
            ),
            new SubjectAuthorization(
                Grants::tokenExchange(),
                $code->grantId,
                $gateway,
                new Subject(self::SUBJECT_OF_THE_FIRST_CLIENT),
                new Scopes([new Scope('invoices.read')]),
                new Scopes([new Scope('invoices.read')]),
                ResourceIndicators::of([Clients::CALENDAR]),
                ResourceIndicators::of([Clients::CALENDAR]),
                new TokenSignIn($this->session->id, AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass())),
                person: $person,
            ),
            Fixtures::now(),
        )->value;
    }

    /**
     * RFC 7523 §2.1: a token of the job runner for the person an assertion named, in the shape the test asks
     * for. Nobody signed in for it here, its grant was drawn for that one response, and it says who it is
     * about, the record of the opaque shape naming them and the "at+jwt" carrying them sealed (issue #588).
     */
    private function tokenOfAnAssertion(string $shape): string
    {
        $runner = Clients::presentingAssertions(
            $this->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            accessTokenShape: $shape === 'opaque' ? Shapes::opaque() : Shapes::jwt(),
        );
        $this->clients->save($runner);
        $authorization = new SubjectAuthorization(
            Grants::jwtBearer(),
            Uuid::v7(),
            $runner,
            $this->user->subject,
            new Scopes([new Scope('invoices.read')]),
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
            ResourceIndicators::of([Clients::CALENDAR]),
            person: $this->user->subject,
        );
        if ($shape === 'opaque') {
            return Tokens::accessToken($this->opaque(), $authorization, Fixtures::now())->value;
        }

        return Tokens::accessToken(
            new JwtAccessTokenIssuer(
                $this->jwts->signer,
                Subjects::publicKind(),
                Algorithms::all(),
                new SymfonyUuidGenerator(),
                $this->persons,
            ),
            $authorization,
            Fixtures::now(),
        )->value;
    }

    private function code(): AuthorizationCode
    {
        $code = Tokens::code('the-code', $this->client, $this->session, Fixtures::now());
        $this->grants->save($code);

        return $code;
    }

    private function tokenOf(AuthorizationCode $code): string
    {
        return Tokens::accessToken($this->opaque(), UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code), Fixtures::now())->value;
    }

    private function opaque(): OpaqueAccessTokenIssuer
    {
        return new OpaqueAccessTokenIssuer($this->tokens, Secrets::drawer());
    }

    /**
     * The same grant in either shape: the record the repository keeps, or the "at+jwt" the issuer mints
     * and the bridge of the core verifies.
     */
    private function tokenOfShape(string $shape, AuthorizationCode $code): string
    {
        if ($shape === 'opaque') {
            return $this->tokenOf($code);
        }

        return Tokens::accessToken(
            new JwtAccessTokenIssuer(
                $this->jwts->signer,
                Subjects::publicKind(),
                Algorithms::all(),
                new SymfonyUuidGenerator(),
                Subjects::sealedPerson(),
            ),
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code),
            Fixtures::now(),
        )->value;
    }
}
