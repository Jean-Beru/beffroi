<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use DateInterval;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Application\Token\TokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Client\AddressedFormat;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Token\ClientAuthorization;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class TokenIssuerTest extends TestCase
{
    private AuthenticationSession $session;

    private Client $client;

    private RequestContext $context;

    private FakeAccessTokenIssuer $accessTokens;

    private FakeIdTokenIssuer $idTokens;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private RecordingEventDispatcher $events;

    private TokenIssuer $issuer;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
        $this->context = Fixtures::context();
        $this->accessTokens = new FakeAccessTokenIssuer();
        $this->idTokens = new FakeIdTokenIssuer();
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->events = new RecordingEventDispatcher();
        $this->issuer = new TokenIssuer($this->accessTokens, $this->idTokens, $this->refreshTokens, Secrets::drawer(), $this->events);
    }

    /**
     * RFC 6749 §4.4.3, OIDC Core §2: an ID token describes who signed in, so an authorization with nobody
     * behind it is answered with an access token and nothing else, whatever its scopes say. What decides is
     * what the authorization is, not the name of the grant that produced it.
     */
    #[Test]
    public function anAuthorizationWithNobodyBehindItIsAnsweredWithAnAccessTokenAlone(): void
    {
        // Given
        $authorization = $this->clientAuthorization();

        // When
        $issued = $this->issuer->issue($authorization, null, $this->context, Fixtures::now());

        // Then
        static::assertNull($issued->idToken);
        static::assertSame([], $this->idTokens->issued);
        static::assertSame([$authorization], $this->accessTokens->issued);
    }

    /**
     * Issue #588: the act names the person the tokens were issued in the name of, by the subject their
     * account carries and not the "sub" the client is answered, so that the journal of that person holds
     * it.
     */
    #[Test]
    public function theIssuanceNamesThePersonTheTokensWereIssuedFor(): void
    {
        // Given
        $authorization = $this->authorizationFromCode();

        // When
        $this->issuer->issue($authorization, null, $this->context, Fixtures::now(), $this->addressed($authorization));

        // Then
        static::assertTrue($this->events->of(TokensIssued::class)[0]->subject()?->equals($this->session->user->subject));
    }

    /**
     * RFC 6749 §4.4: a client that obtained tokens for itself did it in nobody's name, so the act names
     * nobody rather than the client twice.
     */
    #[Test]
    public function theIssuanceToAClientActingForItselfNamesNobody(): void
    {
        // Given
        $authorization = $this->clientAuthorization();

        // When
        $this->issuer->issue($authorization, null, $this->context, Fixtures::now());

        // Then
        static::assertNull($this->events->of(TokensIssued::class)[0]->subject());
    }

    /**
     * OIDC Core §3.1.3.3: an access token and an ID token; the ID token is minted with the access token
     * of the same response, for at_hash.
     */
    #[Test]
    public function itMintsAnAccessTokenAndAnIdTokenWhenOpenidIsRequested(): void
    {
        // Given
        $authorization = $this->authorizationFromCode();

        // When
        $issued = $this->issuer->issue($authorization, null, $this->context, Fixtures::now(), $this->addressed($authorization));

        // Then
        static::assertSame($authorization, $issued->authorization);
        static::assertSame('at:spa:alice-subject:' . Fixtures::now()->getTimestamp(), $issued->accessToken->value);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $issued->accessToken->expiresAt);
        static::assertSame('id:spa:alice-subject:n-0S6_WzA2Mj:' . Fixtures::now()->getTimestamp(), $issued->idToken);
        static::assertSame([$authorization], $this->accessTokens->issued);
        static::assertSame([[$authorization, $issued->accessToken]], $this->idTokens->issued);
    }

    /**
     * The refresh token given goes into the response.
     */
    #[Test]
    public function theRefreshTokenGivenGoesIntoTheResponse(): void
    {
        // Given
        $authorization = $this->authorizationFromCode();
        $refreshToken = $this->issuer->refreshToken(Tokens::family(Fixtures::now(), $authorization->tenant), $authorization, Fixtures::now());

        // When
        $issued = $this->issuer->issue($authorization, $refreshToken, $this->context, Fixtures::now(), $this->addressed($authorization));

        // Then
        static::assertSame($refreshToken, $issued->refreshToken);
    }

    /**
     * The issuance is announced once, with the request context and the record of the refresh token.
     */
    #[Test]
    public function theIssuanceIsAnnouncedOnce(): void
    {
        // Given
        $authorization = $this->authorizationFromCode();
        $refreshToken = $this->issuer->refreshToken(Tokens::family(Fixtures::now(), $authorization->tenant), $authorization, Fixtures::now());

        // When
        $this->issuer->issue($authorization, $refreshToken, $this->context, Fixtures::now(), $this->addressed($authorization));

        // Then
        $events = $this->events->of(TokensIssued::class);
        static::assertCount(1, $events);
        static::assertCount(1, $this->events->events);
        static::assertEquals(Fixtures::now(), $events[0]->occurredAt);
        static::assertSame($this->session->tenant, $events[0]->tenant);
        static::assertSame($this->context, $events[0]->context);
        static::assertSame($authorization->grantId, $events[0]->grantId);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $events[0]->accessTokenExpiresAt);
        static::assertTrue($events[0]->idTokenIssued);
        static::assertSame($refreshToken->token->tokenHash, $events[0]->refreshTokenHash);
    }

    /**
     * RFC 6749 §6 with a scope narrowed below "openid": an access token only.
     */
    #[Test]
    public function itMintsNoIdTokenWithoutOpenid(): void
    {
        // Given
        $authorization = $this->authorizationNarrowedToProfile();

        // When
        $issued = $this->issuer->issue($authorization, null, $this->context, Fixtures::now());

        // Then
        static::assertNull($issued->idToken);
        static::assertSame([], $this->idTokens->issued);
        static::assertFalse($this->events->of(TokensIssued::class)[0]->idTokenIssued);
    }

    /**
     * OIDC Core §3.1.3.3: a response without "openid" carries no ID token, so nothing of the client is read
     * for one, whatever the client publishes.
     */
    #[Test]
    public function theIdTokenOfAResponseWithoutOpenidIsNotAddressed(): void
    {
        // Given
        $this->idTokens->unreadableKeys = new ClientKeysUnavailableException('The keys of the client cannot be read.');

        // When
        $format = $this->issuer->addressIdToken($this->client, new Scopes([new Scope('profile')]));

        // Then
        static::assertNull($format);
    }

    /**
     * OIDC Core §3.1.3.7 (issue #836): the key the ID token is encrypted to is read when the grant addresses
     * it, before it spends anything, and keys the client cannot serve right now are said then.
     */
    #[Test]
    public function keysThatCannotBeReadAreToldWhenTheIdTokenIsAddressed(): void
    {
        // Given
        $this->idTokens->unreadableKeys = new ClientKeysUnavailableException('The keys of the client cannot be read.');

        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIs('The keys of the client cannot be read.');

        // When
        $this->issuer->addressIdToken($this->client, new Scopes([Scope::openid()]));
    }

    /**
     * An ID token is struck for the shape the grant addressed before it spent anything, so a response that
     * carries one the grant did not address is a fault of that grant, said before any ID token leaves.
     */
    #[Test]
    public function anIdTokenTheGrantDidNotAddressIsAFaultOfTheGrant(): void
    {
        // Given
        $authorization = $this->authorizationFromCode();

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The ID token of this response was not addressed before the grant spent what the request presented (OIDC Core section 3.1.3.7).');

        // When
        $this->issuer->issue($authorization, null, $this->context, Fixtures::now());
    }

    #[Test]
    public function itMintsNoRefreshTokenWhenNoneIsGiven(): void
    {
        // Given
        $authorization = $this->authorizationNarrowedToProfile();

        // When
        $issued = $this->issuer->issue($authorization, null, $this->context, Fixtures::now());

        // Then
        static::assertNull($issued->refreshToken);
        static::assertSame([], $this->refreshTokens->all());
        static::assertSame(0, $this->refreshTokens->saves);
        static::assertNull($this->events->of(TokensIssued::class)[0]->refreshTokenHash);
    }

    /**
     * Architecture §4.6: the refresh token is stored as its hash; the value goes to the client only.
     */
    #[Test]
    public function itIssuesARefreshTokenStoredHashed(): void
    {
        // Given
        $token = $this->previousRefreshToken();
        $authorization = UserAuthorization::fromRefreshToken(Grants::refreshToken(), $token, new Scopes([new Scope('profile')]));

        // When
        $issued = $this->issuer->refreshToken($token->family, $authorization, Fixtures::now()->modify('+1 day'));

        // Then
        static::assertSame(1, preg_match('/^[A-Za-z0-9_-]{43}$/', $issued->value));
        static::assertSame(DrawnSecret::digestOf($issued->value), $issued->token->tokenHash);
        static::assertSame([$issued->token], $this->refreshTokens->all());
        static::assertSame($issued->token, $this->refreshTokens->findByTokenHash(DrawnSecret::digestOf($issued->value)));
    }

    /**
     * Architecture §4.6: the refresh token is issued in the family given, for the granted scopes, with
     * the authentication of the authorization.
     */
    #[Test]
    public function theRefreshTokenCarriesTheFamilyTheGrantedScopesAndTheAuthentication(): void
    {
        // Given
        $token = $this->previousRefreshToken();
        $authorization = UserAuthorization::fromRefreshToken(Grants::refreshToken(), $token, new Scopes([new Scope('profile')]));

        // When
        $issued = $this->issuer->refreshToken($token->family, $authorization, Fixtures::now()->modify('+1 day'));

        // Then
        static::assertSame($token->family, $issued->token->family);
        static::assertSame($this->client, $issued->token->client);
        static::assertSame($this->session, $issued->token->session);
        static::assertSame($token->scopes, $issued->token->scopes, 'the granted scopes, not the narrowed ones');
        static::assertEquals($token->authentication->authenticatedAt, $issued->token->authentication->authenticatedAt);
        static::assertSame($token->authentication->methods, $issued->token->authentication->methods);
    }

    /**
     * Architecture §4.6: thirty days sliding.
     */
    #[Test]
    public function theRefreshTokenLivesThirtyDaysFromIssuance(): void
    {
        // Given
        $token = $this->previousRefreshToken();
        $authorization = UserAuthorization::fromRefreshToken(Grants::refreshToken(), $token, new Scopes([new Scope('profile')]));
        $now = Fixtures::now()->modify('+1 day');

        // When
        $issued = $this->issuer->refreshToken($token->family, $authorization, $now);

        // Then
        static::assertEquals($now, $issued->token->issuedAt);
        static::assertEquals($now->modify('+30 days'), $issued->token->expiresAt);
    }

    /**
     * Architecture §4.6: within the family, whose end caps the sliding expiry.
     */
    #[Test]
    public function theRefreshTokenNeverOutlivesItsFamily(): void
    {
        // Given
        $token = $this->previousRefreshToken();
        $authorization = UserAuthorization::fromRefreshToken(Grants::refreshToken(), $token, new Scopes([new Scope('profile')]));

        // When
        $issued = $this->issuer->refreshToken($token->family, $authorization, Fixtures::now()->modify('+85 days'));

        // Then
        static::assertEquals($token->family->expiresAt, $issued->token->expiresAt);
    }

    /**
     * The refresh token is announced with the response, by issue(), not when it is minted.
     */
    #[Test]
    public function mintingARefreshTokenAnnouncesNothing(): void
    {
        // Given
        $token = $this->previousRefreshToken();
        $authorization = UserAuthorization::fromRefreshToken(Grants::refreshToken(), $token, new Scopes([new Scope('profile')]));

        // When
        $this->issuer->refreshToken($token->family, $authorization, Fixtures::now());

        // Then
        static::assertSame([], $this->events->events);
    }

    #[Test]
    public function theRefreshTokenLifetimeIsConfigurable(): void
    {
        // Given
        $token = $this->previousRefreshToken();
        $authorization = UserAuthorization::fromRefreshToken(Grants::refreshToken(), $token, new Scopes([new Scope('profile')]));
        $shortLived = new TokenIssuer($this->accessTokens, $this->idTokens, $this->refreshTokens, Secrets::drawer(), $this->events, new DateInterval('PT1H'));

        // When
        $issued = $shortLived->refreshToken($token->family, $authorization, Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now()->modify('+1 hour'), $issued->token->expiresAt);
    }

    /**
     * An authorization of a client acting for itself, which is the one shape of authorization with
     * nobody behind it (RFC 6749 §4.4).
     */
    private function clientAuthorization(): ClientAuthorization
    {
        return new ClientAuthorization(
            Grants::clientCredentials(),
            Uuid::v7(),
            Clients::service(
                $this->session->tenant,
                new FakePasswordHasher()->hash(Clients::SECRET),
                allowedScopes: new Scopes([Scope::openid()]),
            ),
            new Scopes([Scope::openid()]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );
    }

    private function authorizationFromCode(): UserAuthorization
    {
        return UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
            ['openid', 'profile'],
        ));
    }

    /**
     * What the grant reads before it spends anything: the ID token of the authorization, addressed.
     */
    private function addressed(UserAuthorization $authorization): ?AddressedFormat
    {
        return $this->issuer->addressIdToken($authorization->client, $authorization->scopes);
    }

    private function authorizationNarrowedToProfile(): UserAuthorization
    {
        return UserAuthorization::fromRefreshToken(Grants::refreshToken(), $this->previousRefreshToken(), new Scopes([new Scope('profile')]));
    }

    private function previousRefreshToken(): RefreshToken
    {
        return Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), null, ['openid', 'profile']);
    }
}
