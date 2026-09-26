<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use DateInterval;
use Heidi\Core\Bridge\InMemory\InMemoryLinkedIdentityRepository;
use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Heidi\Core\Domain\Identity\LinkedIdentity;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Client\AuthenticatedClient;
use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Application\Token\JwtBearerGrant;
use Heidi\Oidc\Application\Token\TokenIssuer;
use Heidi\Oidc\Application\Trust\IssuerAssertionValidator;
use Heidi\Oidc\Bridge\InMemory\InMemoryIssuerAssertionReplayGuard;
use Heidi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Token\SubjectAuthorization;
use Heidi\Oidc\Exception\InvalidGrantException;
use Heidi\Oidc\Exception\InvalidScopeException;
use Heidi\Oidc\Exception\InvalidTargetException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Heidi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Heidi\Oidc\Tests\Fixture\FakeTrustedIssuers;
use Heidi\Oidc\Tests\Fixture\Grants;
use Heidi\Oidc\Tests\Fixture\Secrets;
use Heidi\Oidc\Tests\Fixture\TrustedIssuers;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7523 §2.1: an assertion signed by an issuer the tenant trusts, exchanged for an access token for the user
 * it is about. The user is reached through a linked identity of that issuer's source (decision 0002), and no
 * user is created here.
 */
final class JwtBearerGrantTest extends TestCase
{
    private const string REFUSED = 'invalid_grant: The assertion is not one this provider accepts as an authorization (RFC 7523 section 3).';

    private const string EMPLOYEE = 'employee-42';

    private Tenant $tenant;

    private User $user;

    private Client $client;

    private RequestContext $context;

    private FakeIdTokenIssuer $idTokens;

    private FakeTrustedIssuers $issuers;

    private MockClock $clock;

    private JwtBearerGrant $grant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->user = Fixtures::user($this->tenant);
        $this->client = Clients::presentingAssertions($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->clock = new MockClock('2026-09-27T12:00:00+00:00');
        $this->context = Fixtures::context($this->clock->now());
        $this->idTokens = new FakeIdTokenIssuer();
        $refreshTokens = new InMemoryRefreshTokenRepository();
        $identities = new InMemoryLinkedIdentityRepository();
        $identities->save($this->link(self::EMPLOYEE));
        $this->issuers = new FakeTrustedIssuers();
        $this->issuers->trust($this->tenant, TrustedIssuers::workforce());
        $this->grant = new JwtBearerGrant(
            new IssuerAssertionValidator(
                new JwtLibraryCompactJwtReader(),
                new JwtLibraryJwtKeyVerifier(Algorithms::all()->manager()),
                $this->issuers,
                new InMemoryIssuerAssertionReplayGuard(),
                new DateInterval('PT300S'),
                new DateInterval('PT30S'),
            ),
            $identities,
            new PublicSubjectIdentifierResolver(),
            new TokenIssuer(new FakeAccessTokenIssuer(), $this->idTokens, $refreshTokens, Secrets::drawer(), new RecordingEventDispatcher()),
            new SymfonyUuidGenerator(),
            $this->clock,
        );
    }

    #[Test]
    public function itHandlesTheJwtBearerGrantType(): void
    {
        // When / Then
        static::assertTrue($this->grant->grantType()->equals(Grants::jwtBearer()));
    }

    /**
     * RFC 7523 §2.1, decision 0002: the token names the user the linked identity resolved, and is addressed to
     * the resource the request asked for.
     */
    #[Test]
    public function itAuthorizesTheClientForTheUserTheAssertionIsAbout(): void
    {
        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        $authorization = $issued->authorization;
        static::assertInstanceOf(SubjectAuthorization::class, $authorization);
        static::assertSame('alice-subject', $authorization->subject->value);
        static::assertSame($this->client, $authorization->client);
        static::assertSame(['invoices.read'], $authorization->scopes->values());
        static::assertSame([Clients::CALENDAR], $authorization->audience()->values);
        static::assertTrue($authorization->grantType->equals(Grants::jwtBearer()));
    }

    /**
     * OIDC Core §2: the user was authenticated elsewhere and this provider says nothing of how, so there is no
     * "sid", no "acr", no "amr" and no ID token.
     */
    #[Test]
    public function theResponseSaysNothingOfHowTheUserWasAuthenticated(): void
    {
        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        $authorization = $issued->authorization;
        static::assertInstanceOf(SubjectAuthorization::class, $authorization);
        static::assertNull($authorization->signIn);
        static::assertNull($issued->idToken);
        static::assertNull($issued->refreshToken);
        static::assertSame([], $this->idTokens->issued);
    }

    /**
     * RFC 7523 §3, §4: the same assertion presented twice is refused.
     */
    #[Test]
    public function theSameAssertionIsRefusedTheSecondTime(): void
    {
        // Given
        $request = $this->request();
        $this->grant->grant(new AuthenticatedClient($this->client), $request, $this->context);

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $request, $this->context);
    }

    /**
     * Decision 0002: a subject an upstream provider names is a user of this tenant only when a linked identity
     * says so, and this grant creates none.
     */
    #[Test]
    public function anAssertionAboutSomebodyNoIdentityResolvesIsRefused(): void
    {
        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(subject: 'employee-99'), $this->context);
    }

    /**
     * Decision 0002: a linked identity of another source is another identity.
     */
    #[Test]
    public function anIdentityOfAnotherSourceDoesNotResolveTheSubject(): void
    {
        // Given
        $this->issuers->trust($this->tenant, TrustedIssuers::workforce(provider: 'another-source'));

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
    }

    #[Test]
    public function anAssertionAboutAUserThisProviderNoLongerServesIsRefused(): void
    {
        // Given
        $this->user->disable($this->clock->now());

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
    }

    /**
     * OIDC Core §2: "openid" asks for an authentication, and this grant performs none.
     */
    #[Test]
    public function theOpenidScopeIsRefused(): void
    {
        // Given
        $client = Clients::presentingAssertions(
            $this->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            allowedScopes: new Scopes([new Scope('openid')]),
        );

        // Then
        $this->expectException(InvalidScopeException::class);
        $this->expectExceptionMessageIsOrContains('asks for an authentication, and this grant authenticates nobody');

        // When
        $this->grant->grant(new AuthenticatedClient($client), $this->request(scope: 'openid'), $this->context);
    }

    #[Test]
    public function aScopeTheClientDidNotRegisterIsRefused(): void
    {
        // Then
        $this->expectException(InvalidScopeException::class);
        $this->expectExceptionMessageIsOrContains('not allowed for this client');

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(scope: 'payments.write'), $this->context);
    }

    /**
     * RFC 7523 §3: within what the issuer is trusted for, whatever the client registered.
     */
    #[Test]
    public function aScopeTheIssuerIsNotTrustedForIsRefused(): void
    {
        // Given
        $this->issuers->trust($this->tenant, TrustedIssuers::workforce(trustedScopes: ['invoices.read']));

        // Then
        $this->expectException(InvalidScopeException::class);
        $this->expectExceptionMessageIsOrContains('not one the issuer of the assertion is trusted for');

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(scope: 'invoices.write'), $this->context);
    }

    /**
     * RFC 8707 §2: the token is addressed to a resource the request named, never to the client that asked.
     */
    #[Test]
    public function aRequestThatNamesNoResourceIsRefused(): void
    {
        // Then
        $this->expectException(InvalidTargetException::class);
        $this->expectExceptionMessageIsOrContains('issues an access token for a resource, and the request names none');

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(resource: null), $this->context);
    }

    #[Test]
    public function aResourceTheClientDidNotRegisterIsRefused(): void
    {
        // Given
        $client = Clients::presentingAssertions(
            $this->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            resources: [new ResourceIndicator(Clients::CONTACTS)],
        );

        // Then
        $this->expectException(InvalidTargetException::class);
        $this->expectExceptionMessageIsOrContains('not among the resources of this authorization (RFC 8707 section 2.2)');

        // When
        $this->grant->grant(new AuthenticatedClient($client), $this->request(), $this->context);
    }

    private function link(string $subject): LinkedIdentity
    {
        return new LinkedIdentity(
            Uuid::v7(),
            $this->user,
            TrustedIssuers::PROVIDER,
            $subject,
            [],
            Fixtures::now(),
            Fixtures::now(),
        );
    }

    /**
     * @throws OAuth2Exception
     */
    private function request(string $subject = self::EMPLOYEE, ?string $scope = 'invoices.read', ?string $resource = Clients::CALENDAR): RequestParameters
    {
        $parameters = [
            'grant_type' => JwtBearerGrant::GRANT_TYPE,
            'assertion' => TrustedIssuers::assertion($subject, (string) $this->tenant->issuer, $this->clock->now()),
        ];
        if ($scope !== null) {
            $parameters['scope'] = $scope;
        }
        if ($resource !== null) {
            $parameters['resource'] = $resource;
        }

        return RequestParameters::of($parameters);
    }
}
