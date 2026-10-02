<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Application\Token\TokenExchangeGrant;
use Beffroi\Oidc\Application\Token\TokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Exchange\Actor;
use Beffroi\Oidc\Domain\Exchange\MayAct;
use Beffroi\Oidc\Domain\Exchange\PresentedToken;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\SubjectAuthorization;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\InvalidScopeException;
use Beffroi\Oidc\Exception\InvalidTargetException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Exception\UnauthorizedClientException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Tests\Fixture\TokenTypes;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * RFC 8693 §2.1: the grant of a service that acts for somebody else. Delegation when an "actor_token" says who
 * acts, impersonation when nothing does, and nothing widened either way.
 */
final class TokenExchangeGrantTest extends TestCase
{
    private const string SUBJECT_TOKEN = 'the-token-of-the-user';

    private const string ACTOR_TOKEN = 'the-token-of-the-gateway';

    private Tenant $tenant;

    private Client $gateway;

    private AuthenticationSession $session;

    private RequestContext $context;

    private FakeIdTokenIssuer $idTokens;

    private InMemoryRefreshTokenRepository $refreshTokens;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->gateway = Clients::gateway($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->session = Fixtures::session(Fixtures::user($this->tenant));
        $this->context = Fixtures::context(self::clock()->now());
        $this->idTokens = new FakeIdTokenIssuer();
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
    }

    #[Test]
    public function itHandlesTheTokenExchangeGrantType(): void
    {
        // When / Then
        static::assertTrue($this->grant()->grantType()->equals(Grants::tokenExchange()));
    }

    /**
     * RFC 8693 §1.3, §4.1: the new token names the subject of the presented one and the actor in its "act",
     * and it is addressed to the resource the request asked for, inside what the presented token covered.
     */
    #[Test]
    public function aDelegationNamesTheSubjectAndTheActorThatHoldsTheToken(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
            self::ACTOR_TOKEN => $this->gatewayToken(),
        ]);

        // When
        $issued = $grant->grant(
            $this->authenticated(),
            $this->request([
                'actor_token' => self::ACTOR_TOKEN,
                'actor_token_type' => TokenTypeIdentifier::ACCESS_TOKEN,
            ]),
            $this->context,
        );

        // Then
        $authorization = $issued->authorization;
        static::assertInstanceOf(SubjectAuthorization::class, $authorization);
        static::assertSame('alice-subject', $authorization->subject->value);
        static::assertSame(
            [
                'sub' => 'gateway',
            ],
            $authorization->actor?->toClaim(),
        );
        static::assertSame($this->gateway, $authorization->client);
        static::assertSame([Clients::CALENDAR], $authorization->audience()->values);
        static::assertTrue($authorization->grantType->equals(Grants::tokenExchange()));
    }

    /**
     * RFC 8693 §1.3: no "actor_token", nobody acting, and nothing in the token that says otherwise.
     */
    #[Test]
    public function anImpersonationNamesTheSubjectAndNobodyActing(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
        ]);

        // When
        $issued = $grant->grant($this->authenticated(), $this->request(), $this->context);

        // Then
        $authorization = $issued->authorization;
        static::assertInstanceOf(SubjectAuthorization::class, $authorization);
        static::assertSame('alice-subject', $authorization->subject->value);
        static::assertNull($authorization->actor);
    }

    /**
     * RFC 8693 §2.2.1: the response names the type of the token it issued, which no other grant of this
     * provider has to say.
     */
    #[Test]
    public function theResponseNamesTheTypeOfTheTokenItIssued(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
        ]);

        // When
        $response = $grant->grant($this->authenticated(), $this->request(), $this->context)->toResponse();

        // Then
        static::assertSame(TokenTypeIdentifier::ACCESS_TOKEN, $response->parameters()['issued_token_type']);
    }

    /**
     * RFC 8693 §2.2.1: an access token, and nothing else. There is nobody to describe in an ID token, the
     * provider having signed nobody in for this request, and nothing to renew.
     */
    #[Test]
    public function theResponseCarriesNoIdTokenAndNoRefreshToken(): void
    {
        // Given
        $gateway = Clients::gateway(
            $this->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            allowedScopes: new Scopes([new Scope('openid'), new Scope('invoices.read')]),
        );
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(['openid', 'invoices.read']),
        ]);

        // When
        $issued = $grant->grant(new AuthenticatedClient($gateway), $this->request(), $this->context);

        // Then
        static::assertNull($issued->idToken);
        static::assertNull($issued->refreshToken);
        static::assertSame([], $this->idTokens->issued);
        static::assertSame([], $this->refreshTokens->all());
        static::assertNotInstanceOf(UserAuthorizationInterface::class, $issued->authorization);
    }

    /**
     * RFC 8693 §2.1: the scopes of the new token are a subset of the ones the presented token carried.
     */
    #[Test]
    public function theScopesOfTheNewTokenAreNarrowedToWhatTheRequestAsksFor(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
        ]);

        // When
        $issued = $grant->grant(
            $this->authenticated(),
            $this->request([
                'scope' => 'invoices.read',
            ]),
            $this->context,
        );

        // Then
        static::assertSame(['invoices.read'], $issued->authorization->scopes->values());
        static::assertSame(['invoices.read', 'invoices.write'], $issued->authorization->grantedScopes->values());
    }

    /**
     * RFC 8693 §2.1: a request that names no scope narrows nothing and is served what it already held.
     */
    #[Test]
    public function aRequestThatNamesNoScopeKeepsTheOnesOfThePresentedToken(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
        ]);

        // When
        $issued = $grant->grant($this->authenticated(), $this->request(), $this->context);

        // Then
        static::assertSame(['invoices.read', 'invoices.write'], $issued->authorization->scopes->values());
    }

    /**
     * RFC 8693 §2.1: never a superset.
     */
    #[Test]
    public function aWiderScopeIsRefused(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(['invoices.read']),
        ]);

        // Then
        $this->expectException(InvalidScopeException::class);
        $this->expectExceptionMessageIsOrContains('not among the ones the presented token carries (RFC 8693 section 2.1)');

        // When
        $grant->grant(
            $this->authenticated(),
            $this->request([
                'scope' => 'invoices.read invoices.write',
            ]),
            $this->context,
        );
    }

    /**
     * RFC 6749 §3.3: the scopes of a response are among the ones the client that receives it registered, here
     * as in every other grant; a gateway is not served what it never registered because somebody else was.
     */
    #[Test]
    public function aScopeTheClientDidNotRegisterIsRefused(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(['openid']),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('among the ones the client registered (RFC 6749 section 3.3)');

        // When
        $grant->grant($this->authenticated(), $this->request(), $this->context);
    }

    /**
     * RFC 8693 §2.1, RFC 8707 §2: the resource asked for is inside what the presented token was addressed to.
     */
    #[Test]
    public function aResourceOutsideThePresentedTokenIsRefused(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(audience: [Clients::CALENDAR]),
        ]);

        // Then
        $this->expectException(InvalidTargetException::class);
        $this->expectExceptionMessageIsOrContains('not among the resources of this authorization (RFC 8707 section 2.2)');

        // When
        $grant->grant(
            $this->authenticated(),
            $this->request([
                'resource' => Clients::CONTACTS,
            ]),
            $this->context,
        );
    }

    /**
     * RFC 8693 §2.1: a token addressed to the client that holds it was asked for no resource at all, so there
     * is nothing to narrow and the new token could only be addressed further than the old one reached.
     */
    #[Test]
    public function aTokenAddressedToItsOwnClientIsNotExchangeable(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(audience: ['oidc-demo']),
        ]);

        // Then
        $this->expectException(InvalidTargetException::class);
        $this->expectExceptionMessageIsOrContains('addressed to the client that holds it and to no resource');

        // When
        $grant->grant($this->authenticated(), $this->request(), $this->context);
    }

    /**
     * RFC 8693 §2.1: what a client may do is registered, and a client that registered nothing may do nothing.
     */
    #[Test]
    public function aClientThatIsNotRegisteredForAnExchangeIsRefused(): void
    {
        // Given
        $service = Clients::service($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
        ]);

        // Then
        $this->expectException(UnauthorizedClientException::class);
        $this->expectExceptionMessageIsOrContains('not registered for a token exchange (RFC 8693 section 2.1)');

        // When
        $grant->grant(new AuthenticatedClient($service), $this->request(), $this->context);
    }

    /**
     * RFC 8693 §2.1: the types it may present are registered too.
     */
    #[Test]
    public function aTypeOfTokenTheClientDidNotRegisterIsRefused(): void
    {
        // Given
        $gateway = Clients::gateway(
            $this->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            subjectTokenTypes: [TokenTypes::invented()],
        );
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIsOrContains('not a type of token this client may present (RFC 8693 section 2.1)');

        // When
        $grant->grant(new AuthenticatedClient($gateway), $this->request(), $this->context);
    }

    /**
     * RFC 8693 §3: a type the provider is not wired to read is refused before anything is read.
     */
    #[Test]
    public function aTypeOfTokenTheProviderDoesNotReadIsRefused(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIsOrContains('not a type of token this provider reads (RFC 8693 section 3)');

        // When
        $grant->grant(
            $this->authenticated(),
            $this->request([
                'subject_token_type' => TokenTypes::invented()->value,
            ]),
            $this->context,
        );
    }

    /**
     * RFC 8693 §2.1: a client registered to exchange tokens of its own is not thereby registered to act for a
     * user.
     */
    #[Test]
    public function aClientNotRegisteredToActForAUserIsRefusedATokenAboutOne(): void
    {
        // Given
        $gateway = Clients::gateway($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), mayActForAUser: false);
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIsOrContains('not registered to act for a user');

        // When
        $grant->grant(new AuthenticatedClient($gateway), $this->request(), $this->context);
    }

    /**
     * RFC 8693 §4.4: the subject's own word on who may act for them beats the registration of whoever asks.
     */
    #[Test]
    public function anExchangeNoMayActAllowsIsRefused(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(mayAct: new MayAct(new Subject('somebody-else'))),
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIsOrContains('names somebody else as the party that may act for its subject (RFC 8693 section 4.4)');

        // When
        $grant->grant($this->authenticated(), $this->request(), $this->context);
    }

    /**
     * RFC 8693 §4.4: the party named is served.
     */
    #[Test]
    public function anExchangeTheMayActNamesIsServed(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(mayAct: new MayAct(new Subject('gateway'))),
        ]);

        // When
        $issued = $grant->grant($this->authenticated(), $this->request(), $this->context);

        // Then
        $authorization = $issued->authorization;
        static::assertInstanceOf(SubjectAuthorization::class, $authorization);
        static::assertSame('alice-subject', $authorization->subject->value);
    }

    /**
     * RFC 8693 §4.1: a token that already carries an "act" gets the new actor on the outside.
     */
    #[Test]
    public function aSecondExchangeNestsTheChainOfActors(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(actor: new Actor(new Subject('first-hop'))),
            self::ACTOR_TOKEN => $this->gatewayToken(),
        ]);

        // When
        $issued = $grant->grant(
            $this->authenticated(),
            $this->request([
                'actor_token' => self::ACTOR_TOKEN,
                'actor_token_type' => TokenTypeIdentifier::ACCESS_TOKEN,
            ]),
            $this->context,
        );

        // Then
        $authorization = $issued->authorization;
        static::assertInstanceOf(SubjectAuthorization::class, $authorization);
        static::assertSame(
            [
                'sub' => 'gateway',
                'act' => [
                    'sub' => 'first-hop',
                ],
            ],
            $authorization->actor?->toClaim(),
        );
    }

    /**
     * RFC 8693 §4.1: an impersonation of a token that already names an actor keeps the chain it found rather
     * than dropping who has been holding the token.
     */
    #[Test]
    public function anImpersonationKeepsTheChainThePresentedTokenCarried(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(actor: new Actor(new Subject('first-hop'))),
        ]);

        // When
        $issued = $grant->grant($this->authenticated(), $this->request(), $this->context);

        // Then
        $authorization = $issued->authorization;
        static::assertInstanceOf(SubjectAuthorization::class, $authorization);
        static::assertSame(
            [
                'sub' => 'first-hop',
            ],
            $authorization->actor?->toClaim(),
        );
    }

    /**
     * RFC 8693 §2.1: a token is held by whoever holds it, so one naming somebody else would let a client write
     * that somebody else into the "act" of a token nobody else asked for.
     */
    #[Test]
    public function anActorTokenOfAnotherClientIsRefused(): void
    {
        // Given
        $other = Clients::service($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), 'batch');
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
            self::ACTOR_TOKEN => Tokens::presented($other, new Subject('batch')),
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIsOrContains('names the client that presents it (RFC 8693 section 2.1)');

        // When
        $grant->grant(
            $this->authenticated(),
            $this->request([
                'actor_token' => self::ACTOR_TOKEN,
                'actor_token_type' => TokenTypeIdentifier::ACCESS_TOKEN,
            ]),
            $this->context,
        );
    }

    /**
     * RFC 8693 §2.1: the type is required beside the token, and refused without one.
     */
    #[Test]
    public function anActorTokenTypeWithoutAnActorTokenIsRefused(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIsOrContains('names the type of an actor_token, and the request carries none');

        // When
        $grant->grant(
            $this->authenticated(),
            $this->request([
                'actor_token_type' => TokenTypeIdentifier::ACCESS_TOKEN,
            ]),
            $this->context,
        );
    }

    /**
     * RFC 8693 §2.1: this provider issues access tokens, so a request that asks for another type asks for
     * something it cannot answer.
     */
    #[Test]
    public function anotherRequestedTokenTypeIsRefused(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIsOrContains('and the request asks for another one (RFC 8693 section 2.1)');

        // When
        $grant->grant(
            $this->authenticated(),
            $this->request([
                'requested_token_type' => 'urn:ietf:params:oauth:token-type:refresh_token',
            ]),
            $this->context,
        );
    }

    /**
     * RFC 8693 §2.1: what a token of this provider is addressed to is named by the resource indicators of
     * RFC 8707 §2 and by nothing else, so a logical name beside them is refused rather than ignored.
     */
    #[Test]
    public function anAudienceParameterIsRefused(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
        ]);

        // Then
        $this->expectException(InvalidTargetException::class);
        $this->expectExceptionMessageIsOrContains('named by the resource parameter (RFC 8707 section 2)');

        // When
        $grant->grant(
            $this->authenticated(),
            $this->request([
                'audience' => 'calendar',
            ]),
            $this->context,
        );
    }

    /**
     * RFC 8693 §2.2.2: a token this provider no longer honours is refused, and what it says of it is that it
     * is not good.
     */
    #[Test]
    public function aTokenThisProviderDoesNotHonourIsRefused(): void
    {
        // Given
        $grant = $this->grant();

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIsOrContains('not one this provider honours (RFC 8693 section 2.2.2)');

        // When
        $grant->grant($this->authenticated(), $this->request(), $this->context);
    }

    /**
     * RFC 8693 §2.1: the new token descends from the grant the presented one descended from, so taking that
     * grant back takes both, and a session that ended refuses both.
     */
    #[Test]
    public function theNewTokenDescendsFromTheGrantThePresentedOneDescendedFrom(): void
    {
        // Given
        $presented = $this->userToken();
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $presented,
        ]);

        // When
        $issued = $grant->grant($this->authenticated(), $this->request(), $this->context);

        // Then
        static::assertTrue($issued->authorization->grantId->equals($presented->grantId));
    }

    /**
     * RFC 9068 §2.2.1: the sign-in the presented token descended from, carried unchanged, so that the provider
     * keeps asking of the new token what it asked of the old one.
     */
    #[Test]
    public function theNewTokenCarriesTheSignInThePresentedOneNamed(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
        ]);

        // When
        $issued = $grant->grant($this->authenticated(), $this->request(), $this->context);

        // Then
        $authorization = $issued->authorization;
        static::assertInstanceOf(SubjectAuthorization::class, $authorization);
        static::assertTrue($authorization->signIn?->sessionId->equals($this->session->id));
    }

    /**
     * RFC 6749 §4.4: a token a client holds for itself names no sign-in, and the token it is exchanged for
     * names none either.
     */
    #[Test]
    public function aTokenOfAClientActingForItselfIsExchangedWithoutASignIn(): void
    {
        // Given
        $service = Clients::service($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $grant = $this->grant([
            self::SUBJECT_TOKEN => Tokens::presented($service, new Subject('batch')),
        ]);

        // When
        $issued = $grant->grant($this->authenticated(), $this->request(), $this->context);

        // Then
        $authorization = $issued->authorization;
        static::assertInstanceOf(SubjectAuthorization::class, $authorization);
        static::assertSame('batch', $authorization->subject->value);
        static::assertNull($authorization->signIn);
    }

    /**
     * @param array<string, PresentedToken> $tokens
     */
    private function grant(array $tokens = []): TokenExchangeGrant
    {
        $clock = self::clock();

        return new TokenExchangeGrant(
            TokenTypes::served($tokens),
            new TokenIssuer(new FakeAccessTokenIssuer(), $this->idTokens, $this->refreshTokens, Secrets::drawer(), new RecordingEventDispatcher()),
            $clock,
        );
    }

    /**
     * @param list<string> $scopes
     * @param list<string>|null $audience
     */
    private function userToken(
        array $scopes = ['invoices.read', 'invoices.write'],
        ?array $audience = null,
        ?Actor $actor = null,
        ?MayAct $mayAct = null,
    ): PresentedToken {
        return Tokens::presented(
            Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), resources: Clients::resources()),
            $this->session->user->subject,
            $this->session,
            $scopes,
            $audience,
            actor: $actor,
            mayAct: $mayAct,
        );
    }

    private function gatewayToken(): PresentedToken
    {
        return Tokens::presented($this->gateway, new Subject('gateway'));
    }

    private function authenticated(): AuthenticatedClient
    {
        return new AuthenticatedClient($this->gateway);
    }

    /**
     * @param array<string, string> $overrides
     *
     * @throws OAuth2Exception
     */
    private function request(array $overrides = []): RequestParameters
    {
        return RequestParameters::of([
            'grant_type' => TokenExchangeGrant::GRANT_TYPE,
            'subject_token' => self::SUBJECT_TOKEN,
            'subject_token_type' => TokenTypeIdentifier::ACCESS_TOKEN,
            'resource' => Clients::CALENDAR,
            ...$overrides,
        ]);
    }

    private static function clock(): MockClock
    {
        return new MockClock('2026-09-27T12:00:00+00:00');
    }
}
