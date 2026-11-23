<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use function array_filter;
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
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\SubjectAuthorization;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * RFC 8693 §2.1
 */
final class TokenExchangeGrantTest extends TestCase
{
    private const string SUBJECT_TOKEN = 'the-token-of-the-user';

    private const string ACTOR_TOKEN = 'the-token-of-the-gateway';

    private const string CLIENT_URI = 'https://app.example/';

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
     * RFC 8693 §1.3, §4.1
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
     * RFC 8693 §1.3
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

    #[Test]
    public function theAuthorizationNamesThePersonThePresentedTokenWasReadBackAs(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
        ]);

        // When
        $issued = $grant->grant($this->authenticated(), $this->request(), $this->context);

        // Then
        static::assertTrue($issued->authorization->person()?->equals($this->session->user->subject));
    }

    /**
     * RFC 6749 §4.4
     */
    #[Test]
    public function theAuthorizationOfAnExchangedClientTokenNamesNobody(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->gatewayToken(),
        ]);

        // When
        $issued = $grant->grant($this->authenticated(), $this->request(), $this->context);

        // Then
        static::assertNull($issued->authorization->person());
    }

    /**
     * RFC 8693 §2.2.1
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
     * RFC 8693 §2.2.1
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
     * RFC 8693 §2.1
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
     * RFC 8693 §2.1
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
     * RFC 8693 §2.1
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
     * RFC 6749 §3.3, §5.2
     *
     * @param array<string, string|null> $parameters
     */
    #[Test]
    #[DataProvider('provideScopesTheClientDidNotRegister')]
    public function aScopeTheClientDidNotRegisterIsRefused(array $parameters): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(['invoices.read', 'openid']),
        ]);

        // Then
        $this->expectException(InvalidScopeException::class);
        $this->expectExceptionMessageIs('invalid_scope: The requested scope is not allowed for this client.');

        // When
        $grant->grant($this->authenticated(), $this->request($parameters), $this->context);
    }

    /**
     * @return iterable<string, array{array<string, string|null>}>
     */
    public static function provideScopesTheClientDidNotRegister(): iterable
    {
        yield 'named by the request' => [[
            'scope' => 'invoices.read openid',
        ]];
        yield 'taken from the presented token by a request that names none' => [[]];
    }

    /**
     * RFC 8707 §2, RFC 6749 §5.2
     *
     * @param array<string, string|null> $parameters
     */
    #[Test]
    #[DataProvider('provideResourcesTheClientDidNotRegister')]
    public function aResourceTheClientDidNotRegisterIsRefused(array $parameters): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(audience: [Clients::CALENDAR, Clients::CONTACTS]),
        ]);
        $gateway = Clients::gateway($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), resources: [new ResourceIndicator(Clients::CALENDAR)]);

        // Then
        $this->expectException(InvalidTargetException::class);
        $this->expectExceptionMessageIs('invalid_target: The requested resource is not one this client is registered for (RFC 8707 section 2).');

        // When
        $grant->grant(new AuthenticatedClient($gateway), $this->request($parameters), $this->context);
    }

    /**
     * @return iterable<string, array{array<string, string|null>}>
     */
    public static function provideResourcesTheClientDidNotRegister(): iterable
    {
        yield 'named by the request' => [[
            'resource' => Clients::CONTACTS,
        ]];
        yield 'taken from the presented token by a request that names none' => [[
            'resource' => null,
        ]];
    }

    /**
     * RFC 8693 §2.1, RFC 8707 §2
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
     * RFC 8693 §2.1
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
     * RFC 8693 §2.1, RFC 8707 §2
     */
    #[Test]
    public function aTokenAddressedToItsOwnClientNamedByAnUriIsNotExchangeable(): void
    {
        // Given
        $hash = new FakePasswordHasher()->hash(Clients::SECRET);
        $gateway = Clients::gateway($this->tenant, $hash, resources: [new ResourceIndicator(self::CLIENT_URI)]);
        $grant = $this->grant([
            self::SUBJECT_TOKEN => Tokens::presented(
                Clients::confidential($this->tenant, $hash, clientId: self::CLIENT_URI),
                $this->session->user->subject,
                $this->session,
                audience: [self::CLIENT_URI],
            ),
        ]);

        // Then
        $this->expectException(InvalidTargetException::class);
        $this->expectExceptionMessageIsOrContains('addressed to the client that holds it and to no resource');

        // When
        $grant->grant(new AuthenticatedClient($gateway), $this->request(['resource' => null]), $this->context);
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    public function aTokenAddressedToSomethingThatIsNotAResourceIsNotExchangeable(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(audience: ['somebody-else']),
        ]);

        // Then
        $this->expectException(InvalidTargetException::class);
        $this->expectExceptionMessageIsOrContains('addressed to something that is not a resource');

        // When
        $grant->grant($this->authenticated(), $this->request(), $this->context);
    }

    /**
     * RFC 8693 §2.1
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
     * RFC 8693 §2.1
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
     * RFC 8693 §3
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
     * RFC 8693 §2.1
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
     * RFC 8693 §2.1, RFC 7523 §2.1
     */
    #[Test]
    public function aClientNotRegisteredToActForAUserIsRefusedATokenThatNamesOneNobodySignedInFor(): void
    {
        // Given
        $gateway = Clients::gateway($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), mayActForAUser: false);
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->tokenOfAnAssertion(),
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIsOrContains('not registered to act for a user');

        // When
        $grant->grant(new AuthenticatedClient($gateway), $this->request(), $this->context);
    }

    /**
     * RFC 8693 §4.4
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
     * RFC 8693 §4.4
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
     * RFC 8693 §4.1
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
     * RFC 8693 §4.1
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
     * RFC 8693 §4.4
     */
    #[Test]
    public function anImpersonationIsRefusedWhenTheMayActNamesTheActorThePresentedTokenCarries(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(actor: new Actor(new Subject('first-hop')), mayAct: new MayAct(new Subject('first-hop'))),
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIsOrContains('names somebody else as the party that may act for its subject (RFC 8693 section 4.4)');

        // When
        $grant->grant($this->authenticated(), $this->request(), $this->context);
    }

    /**
     * RFC 8693 §4.4
     */
    #[Test]
    public function anImpersonationByTheClientTheMayActNamesIsServedWhateverActorThePresentedTokenCarries(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(actor: new Actor(new Subject('first-hop')), mayAct: new MayAct(new Subject('gateway'))),
        ]);

        // When
        $issued = $grant->grant($this->authenticated(), $this->request(), $this->context);

        // Then
        $authorization = $issued->authorization;
        static::assertInstanceOf(SubjectAuthorization::class, $authorization);
        static::assertSame('alice-subject', $authorization->subject->value);
    }

    /**
     * RFC 8693 §2.1
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
        $this->expectExceptionMessageIsOrContains('holds for itself, and names no person (RFC 8693 section 2.1)');

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
     * RFC 8693 §2.1, §4.1
     */
    #[Test]
    public function anActorTokenTheClientHoldsForAPersonIsRefused(): void
    {
        // Given
        $grant = $this->grant([
            self::SUBJECT_TOKEN => $this->userToken(),
            self::ACTOR_TOKEN => Tokens::presented($this->gateway, $this->session->user->subject, $this->session),
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIsOrContains('holds for itself, and names no person (RFC 8693 section 2.1)');

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
     * RFC 8693 §2.1
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
     * RFC 8693 §2.1
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
     * RFC 8693 §2.1, RFC 8707 §2
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
     * RFC 8693 §2.2.2
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
     * RFC 8693 §2.1
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
     * RFC 9068 §2.2.1
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
     * RFC 6749 §4.4
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

    /**
     * RFC 7523 §2.1
     */
    private function tokenOfAnAssertion(): PresentedToken
    {
        return Tokens::presented(
            Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), resources: Clients::resources()),
            $this->session->user->subject,
            person: $this->session->user->subject,
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
     * @param array<string, string|null> $overrides null for a parameter the request does not carry
     *
     * @throws OAuth2Exception
     */
    private function request(array $overrides = []): RequestParameters
    {
        return RequestParameters::of(array_filter(
            [
                'grant_type' => TokenExchangeGrant::GRANT_TYPE,
                'subject_token' => self::SUBJECT_TOKEN,
                'subject_token_type' => TokenTypeIdentifier::ACCESS_TOKEN,
                'resource' => Clients::CALENDAR,
                ...$overrides,
            ],
            static fn (?string $value): bool => $value !== null,
        ));
    }

    private static function clock(): MockClock
    {
        return new MockClock('2026-09-27T12:00:00+00:00');
    }
}
