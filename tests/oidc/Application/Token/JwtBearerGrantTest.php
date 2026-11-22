<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Core\Bridge\InMemory\InMemoryLinkedIdentityRepository;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Application\Token\JwtBearerGrant;
use Beffroi\Oidc\Application\Token\TokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\SubjectAuthorization;
use Beffroi\Oidc\Exception\InvalidGrantException;
use Beffroi\Oidc\Exception\InvalidScopeException;
use Beffroi\Oidc\Exception\InvalidTargetException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\FakeTrustedIssuers;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Tests\Fixture\TrustedIssuers;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7523 §2.1, Decision 0002
 */
final class JwtBearerGrantTest extends TestCase
{
    private const string REFUSED = 'invalid_grant: The assertion is not one this provider accepts as an authorization (RFC 7523 section 3).';

    private const string EMPLOYEE = 'employee-42';

    private Tenant $tenant;

    private User $user;

    private Client $client;

    private RequestContext $context;

    private FakeAccessTokenIssuer $accessTokens;

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
        $this->accessTokens = new FakeAccessTokenIssuer();
        $this->idTokens = new FakeIdTokenIssuer();
        $refreshTokens = new InMemoryRefreshTokenRepository();
        $identities = new InMemoryLinkedIdentityRepository();
        $identities->save($this->link(self::EMPLOYEE));
        $this->issuers = new FakeTrustedIssuers();
        $this->issuers->trust($this->tenant, TrustedIssuers::workforce());
        $this->grant = new JwtBearerGrant(
            TrustedIssuers::validator($this->issuers),
            $identities,
            Subjects::publicKind(),
            new TokenIssuer($this->accessTokens, $this->idTokens, $refreshTokens, Secrets::drawer(), new RecordingEventDispatcher()),
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
     * RFC 7523 §2.1, Decision 0002
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
     * OIDC Core §8.1
     */
    #[Test]
    public function theAuthorizationNamesThePersonTheAssertionWasValidatedFor(): void
    {
        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertSame('alice-subject', $issued->authorization->person()?->value);
    }

    /**
     * OIDC Core §2
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
     * RFC 7523 §3, §4
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
     * RFC 7523 §3
     */
    #[Test]
    public function anAssertionLeftUnspentByAnOutageIsExchangedOnceTheKmsAnswers(): void
    {
        // Given
        $request = $this->request();
        $this->accessTokens->kmsOutage = new KmsUnavailableException('The KMS did not answer.');
        try {
            $this->grant->grant(new AuthenticatedClient($this->client), $request, $this->context);
        } catch (KmsUnavailableException) {
        }
        $this->accessTokens->kmsOutage = null;

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $request, $this->context);

        // Then
        static::assertSame('alice-subject', $issued->authorization->person()?->value);
    }

    /**
     * RFC 7523 §3
     */
    #[Test]
    #[DataProvider('provideRequestsRefusedForWhatTheyAsk')]
    public function theAssertionOfARefusedRequestIsExchangedByTheNextOne(?string $scope, ?string $resource): void
    {
        // Given
        $assertion = $this->assertion();
        try {
            $this->grant->grant(
                new AuthenticatedClient($this->client),
                $this->request(scope: $scope, resource: $resource, assertion: $assertion),
                $this->context,
            );
        } catch (OAuth2Exception) {
        }

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(assertion: $assertion), $this->context);

        // Then
        static::assertSame('alice-subject', $issued->authorization->person()?->value);
    }

    /**
     * @return iterable<string, array{string|null, string|null}>
     */
    public static function provideRequestsRefusedForWhatTheyAsk(): iterable
    {
        yield 'a scope the client did not register' => ['payments.write', Clients::CALENDAR];
        yield 'no resource' => ['invoices.read', null];
    }

    /**
     * Decision 0002
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
     * Decision 0002
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
     * OIDC Core §2
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
     * RFC 7523 §3
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
     * RFC 8707 §2
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
    private function request(
        string $subject = self::EMPLOYEE,
        ?string $scope = 'invoices.read',
        ?string $resource = Clients::CALENDAR,
        ?string $assertion = null,
    ): RequestParameters {
        $parameters = [
            'grant_type' => JwtBearerGrant::GRANT_TYPE,
            'assertion' => $assertion ?? $this->assertion($subject),
        ];
        if ($scope !== null) {
            $parameters['scope'] = $scope;
        }
        if ($resource !== null) {
            $parameters['resource'] = $resource;
        }

        return RequestParameters::of($parameters);
    }

    /**
     * RFC 7523 §3
     */
    private function assertion(string $subject = self::EMPLOYEE): string
    {
        return TrustedIssuers::assertion($subject, (string) $this->tenant->issuer, $this->clock->now());
    }
}
