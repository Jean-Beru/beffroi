<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Key;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use DateInterval;
use Beffroi\Core\Application\Key\RetirementWindow;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Authorization\AuthorizationRequestParser;
use Beffroi\Oidc\Application\Authorization\RequestObjectValidator;
use Beffroi\Oidc\Application\Authorization\ResponseDocumentIssuer;
use Beffroi\Oidc\Application\Client\RegisteredClients;
use Beffroi\Oidc\Application\Claims\StandardClaimsProvider;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Application\Key\AccessTokenJwsKind;
use Beffroi\Oidc\Application\Key\IdTokenJwsKind;
use Beffroi\Oidc\Application\Key\LogoutTokenJwsKind;
use Beffroi\Oidc\Application\Key\PushedRequestJweKind;
use Beffroi\Oidc\Application\Key\RequestObjectJweKind;
use Beffroi\Oidc\Application\Key\ResponseDocumentJwsKind;
use Beffroi\Oidc\Application\PushedAuthorization\PushedAuthorizationHandler;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Application\Token\JwtIdTokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryPushedAuthorizationRecordRepository;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\ChallengeMethods;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\FakeClientLoadBudget;
use Beffroi\Oidc\Tests\Fixture\FakeLogoutTokenDelivery;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\Proofs;
use Beffroi\Oidc\Tests\Fixture\RequestObjects;
use Beffroi\Oidc\Tests\Fixture\ServedChannels;
use Beffroi\Oidc\Tests\Fixture\ServedModes;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use Beffroi\Oidc\Tests\Fixture\Shapes;

/**
 * Architecture §3.3: the kinds of artifact the module binds to a key of the tenant, as the rotation of the
 * core reads them to date the retirement of a key. A JWS the module issues holds back a key that signs; a
 * JWE a client may still be sending holds back a key it is encrypted to.
 */
final class KeyBoundArtifactsTest extends TestCase
{
    private Tenant $tenant;

    private Jwts $jwts;

    private InMemoryClientRepository $clients;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->jwts = new Jwts($this->tenant);
        $this->clients = new InMemoryClientRepository();
    }

    #[Test]
    public function theIdTokenLivesAsLongAsItsIssuerSays(): void
    {
        // Given
        $kind = new IdTokenJwsKind(
            new JwtIdTokenIssuer(
                $this->jwts->documents,
                Subjects::publicKind(),
                new StandardClaimsProvider(),
                Algorithms::all(),
                new DateInterval('PT1H'),
            ),
        );

        // When / Then
        static::assertEquals(new DateInterval('PT1H'), $kind->longestLifetime($this->tenant));
    }

    #[Test]
    public function theSelfContainedAccessTokenLivesAsLongAsItsIssuerSaysWhenAClientReceivesIt(): void
    {
        // Given
        $this->clients->save(Clients::public($this->tenant));
        $kind = new AccessTokenJwsKind(
            new JwtAccessTokenIssuer(
                $this->jwts->signer,
                Subjects::publicKind(),
                Algorithms::all(),
                new SymfonyUuidGenerator(),
                Subjects::sealedPerson(),
                new DateInterval('PT20M'),
            ),
            new RegisteredClients([$this->clients]),
        );

        // When / Then
        static::assertEquals(new DateInterval('PT20M'), $kind->longestLifetime($this->tenant));
    }

    /**
     * JARM §2.1 and issue #155: the signed authorization response is a fourth kind of JWS, and it says
     * how long it stays verifiable rather than leaving the window to the two token lifetimes.
     */
    #[Test]
    public function theSignedAuthorizationResponseLivesAsLongAsItsIssuerSaysWhenASignedModeIsWired(): void
    {
        // Given
        $kind = new ResponseDocumentJwsKind($this->documents(new DateInterval('PT30M')), ServedModes::signedToo());

        // When / Then
        static::assertEquals(new DateInterval('PT30M'), $kind->longestLifetime($this->tenant));
    }

    /**
     * A deployment that answers in "query" and "form_post" alone signs no such document.
     */
    #[Test]
    public function theSignedAuthorizationResponseIsNotIssuedWhenNoSignedModeIsWired(): void
    {
        // Given
        $kind = new ResponseDocumentJwsKind($this->documents(new DateInterval('PT30M')), ServedModes::queryAndFormPost());

        // When / Then
        static::assertNull($kind->longestLifetime($this->tenant));
    }

    /**
     * The acceptance of issue #163: a tenant that serves JARM keeps a key published long enough for the
     * document it signed to be verified, even when both token lifetimes are shorter than that.
     */
    #[Test]
    public function theRetirementWindowOfATenantThatServesJarmCoversTheResponseDocument(): void
    {
        // Given
        $this->clients->save(Clients::public($this->tenant));
        $window = new RetirementWindow([
            new IdTokenJwsKind(
                new JwtIdTokenIssuer(
                    $this->jwts->documents,
                    Subjects::publicKind(),
                    new StandardClaimsProvider(),
                    Algorithms::all(),
                    new DateInterval('PT2M'),
                ),
            ),
            new AccessTokenJwsKind(
                new JwtAccessTokenIssuer(
                    $this->jwts->signer,
                    Subjects::publicKind(),
                    Algorithms::all(),
                    new SymfonyUuidGenerator(),
                    Subjects::sealedPerson(),
                    new DateInterval('PT2M'),
                ),
                new RegisteredClients([$this->clients]),
            ),
            new ResponseDocumentJwsKind($this->documents(new DateInterval('PT5M')), ServedModes::signedToo()),
        ]);

        // When / Then
        static::assertEquals(
            Fixtures::now()->add(new DateInterval('PT5M')),
            $window->dueAt($this->tenant, KeyUse::Signature, Fixtures::now()),
        );
    }

    /**
     * Back-Channel Logout 1.0 §2.5 and issue #155: a logout token carries no "exp", RFC 8417 §2.2 not
     * recommending one, so what it declares is how long its delivery may still be tried.
     */
    #[Test]
    public function theLogoutTokenLivesAsLongAsItsDeliveryMayBeTried(): void
    {
        // Given
        $kind = new LogoutTokenJwsKind(new FakeLogoutTokenDelivery(new DateInterval('PT4M')), ServedChannels::backChannelOnly());

        // When / Then
        static::assertEquals(new DateInterval('PT4M'), $kind->longestLifetime($this->tenant));
    }

    /**
     * Front-Channel Logout 1.0 §3: a deployment that loads a logout URI in a frame posts no token, and
     * signs none.
     */
    #[Test]
    public function theLogoutTokenIsNotIssuedWhenNothingPostsOne(): void
    {
        // Given
        $kind = new LogoutTokenJwsKind(new FakeLogoutTokenDelivery(new DateInterval('PT4M')), ServedChannels::frontChannelOnly());

        // When / Then
        static::assertNull($kind->longestLifetime($this->tenant));
    }

    /**
     * The acceptance of issue #155: an operator who lowers both token lifetimes under the patience of the
     * sender does not shrink the window under it, and a logout token delivered on a late retry still
     * names a key the JWK Set publishes.
     */
    #[Test]
    public function theRetirementWindowOfATenantThatPostsLogoutTokensCoversTheirDelivery(): void
    {
        // Given
        $this->clients->save(Clients::public($this->tenant));
        $window = new RetirementWindow([
            new IdTokenJwsKind(
                new JwtIdTokenIssuer(
                    $this->jwts->documents,
                    Subjects::publicKind(),
                    new StandardClaimsProvider(),
                    Algorithms::all(),
                    new DateInterval('PT1M'),
                ),
            ),
            new AccessTokenJwsKind(
                new JwtAccessTokenIssuer(
                    $this->jwts->signer,
                    Subjects::publicKind(),
                    Algorithms::all(),
                    new SymfonyUuidGenerator(),
                    Subjects::sealedPerson(),
                    new DateInterval('PT1M'),
                ),
                new RegisteredClients([$this->clients]),
            ),
            new LogoutTokenJwsKind(new FakeLogoutTokenDelivery(new DateInterval('PT4M')), ServedChannels::backChannelOnly()),
        ]);

        // When / Then
        static::assertEquals(
            Fixtures::now()->add(new DateInterval('PT4M')),
            $window->dueAt($this->tenant, KeyUse::Signature, Fixtures::now()),
        );
    }

    /**
     * An opaque access token depends on no key: a tenant whose clients all receive one issues no such JWS.
     */
    #[Test]
    public function theSelfContainedAccessTokenIsNotIssuedWhenEveryClientReceivesAnOpaqueOne(): void
    {
        // Given
        $this->clients->save(Clients::confidential(
            $this->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            accessTokenShape: Shapes::opaque(),
        ));
        $kind = new AccessTokenJwsKind(
            new JwtAccessTokenIssuer($this->jwts->signer, Subjects::publicKind(), Algorithms::all(), new SymfonyUuidGenerator(), Subjects::sealedPerson()),
            new RegisteredClients([$this->clients]),
        );

        // When / Then
        static::assertNull($kind->longestLifetime($this->tenant));
    }

    /**
     * Issue #164: an encryption key stays openable while a client may still be sending a request object
     * encrypted to it, which is how long the provider lets such an object stand.
     */
    #[Test]
    public function theRequestObjectLivesAsLongAsTheProviderLetsOneStand(): void
    {
        // Given
        $kind = new RequestObjectJweKind(new RequestObjectValidator(new DateInterval('PT10M'), new DateInterval('PT30S')));

        // When / Then
        static::assertEquals(new DateInterval('PT10M'), $kind->longestLifetime($this->tenant));
    }

    /**
     * RFC 9126 §2: so does a request the client pushes, for as long as the endpoint says.
     */
    #[Test]
    public function thePushedRequestLivesAsLongAsTheEndpointSays(): void
    {
        // Given
        $kind = new PushedRequestJweKind($this->pushedRequests(new DateInterval('PT90S')));

        // When / Then
        static::assertEquals(new DateInterval('PT90S'), $kind->longestLifetime($this->tenant));
    }

    /**
     * The acceptance of issue #164: the two uses do not share a window. An encryption key retires on what
     * a client may still be encrypting to it, and never on the lifetime of a token it never signed; the
     * key that signs retires on the tokens, and never on the request objects.
     */
    #[Test]
    public function eachUseIsHeldBackByTheArtifactsOfItsOwnUse(): void
    {
        // Given
        $this->clients->save(Clients::public($this->tenant));
        $window = new RetirementWindow([
            new IdTokenJwsKind(
                new JwtIdTokenIssuer(
                    $this->jwts->documents,
                    Subjects::publicKind(),
                    new StandardClaimsProvider(),
                    Algorithms::all(),
                    new DateInterval('PT2M'),
                ),
            ),
            new AccessTokenJwsKind(
                new JwtAccessTokenIssuer(
                    $this->jwts->signer,
                    Subjects::publicKind(),
                    Algorithms::all(),
                    new SymfonyUuidGenerator(),
                    Subjects::sealedPerson(),
                    new DateInterval('PT2M'),
                ),
                new RegisteredClients([$this->clients]),
            ),
            new RequestObjectJweKind(new RequestObjectValidator(new DateInterval('PT10M'), new DateInterval('PT30S'))),
            new PushedRequestJweKind($this->pushedRequests(new DateInterval('PT90S'))),
        ]);

        // When / Then
        static::assertEquals(
            Fixtures::now()->add(new DateInterval('PT2M')),
            $window->dueAt($this->tenant, KeyUse::Signature, Fixtures::now()),
        );
        static::assertEquals(
            Fixtures::now()->add(new DateInterval('PT10M')),
            $window->dueAt($this->tenant, KeyUse::Encryption, Fixtures::now()),
        );
    }

    private function pushedRequests(DateInterval $lifetime): PushedAuthorizationHandler
    {
        $clock = new MockClock(Fixtures::now());

        return new PushedAuthorizationHandler(
            new ClientAuthenticator(
                $this->clients,
                Methods::all(new FakePasswordHasher()),
                Methods::requestParser(),
                $clock,
                new RecordingEventDispatcher(),
                new FakeClientLoadBudget(),
            ),
            Proofs::verifier(),
            new Endpoints(),
            new AuthorizationRequestParser($this->clients, ServedModes::queryAndFormPost(), AuthorizationDetailTypes::served(), ChallengeMethods::s256()),
            RequestObjects::resolver($this->clients, $clock),
            new InMemoryPushedAuthorizationRecordRepository(),
            Secrets::drawer(),
            $clock,
            $lifetime,
        );
    }

    private function documents(DateInterval $lifetime): ResponseDocumentIssuer
    {
        return new ResponseDocumentIssuer($this->jwts->documents, new MockClock(Fixtures::now()), $lifetime);
    }
}
