<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Key;

use DateInterval;
use Heidi\Core\Application\Key\TenantKeyRotator;
use Heidi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Heidi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use Heidi\Core\Tests\Fixture\PrecomputedKeyPairGenerator;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Authorization\AuthorizationRequestParser;
use Heidi\Oidc\Application\Authorization\RequestObjectValidator;
use Heidi\Oidc\Application\Authorization\ResponseDocumentIssuer;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Application\Key\AccessTokenJwsKind;
use Heidi\Oidc\Application\Key\IdTokenJwsKind;
use Heidi\Oidc\Application\Key\LogoutTokenJwsKind;
use Heidi\Oidc\Application\Key\PushedRequestJweKind;
use Heidi\Oidc\Application\Key\RequestObjectJweKind;
use Heidi\Oidc\Application\Key\ResponseDocumentJwsKind;
use Heidi\Oidc\Application\PushedAuthorization\PushedAuthorizationHandler;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryPushedAuthorizationRequestRepository;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Endpoints;
use Heidi\Oidc\Tests\Fixture\FakeLogoutTokenDelivery;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\Methods;
use Heidi\Oidc\Tests\Fixture\Proofs;
use Heidi\Oidc\Tests\Fixture\RequestObjects;
use Heidi\Oidc\Tests\Fixture\ServedChannels;
use Heidi\Oidc\Tests\Fixture\ServedModes;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

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
                new PublicSubjectIdentifierResolver(),
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
            new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), Algorithms::all(), new DateInterval('PT20M')),
            $this->clients,
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
        $clock = new MockClock(Fixtures::now());
        $rotator = new TenantKeyRotator(
            new InMemoryTenantKeyRepository(),
            new PrecomputedKeyPairGenerator([Keys::pair(), Keys::otherPair()]),
            Keys::sealer(),
            [
                new IdTokenJwsKind(
                    new JwtIdTokenIssuer(
                        $this->jwts->documents,
                        new PublicSubjectIdentifierResolver(),
                        new StandardClaimsProvider(),
                        Algorithms::all(),
                        new DateInterval('PT2M'),
                    ),
                ),
                new AccessTokenJwsKind(
                    new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), Algorithms::all(), new DateInterval('PT2M')),
                    $this->clients,
                ),
                new ResponseDocumentJwsKind($this->documents(new DateInterval('PT5M')), ServedModes::signedToo()),
            ],
            new DateInterval('PT6M'),
            $clock,
            new RecordingEventDispatcher(),
        );
        $context = RequestContext::unknown($clock->now());
        $first = $rotator->rotate($this->tenant, Algorithms::rs256(), $context);

        // When
        $rotator->rotate($this->tenant, Algorithms::rs256(), $context);

        // Then
        static::assertEquals($clock->now()->add(new DateInterval('PT5M')), $first->retirementDueAt);
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
        $clock = new MockClock(Fixtures::now());
        $rotator = new TenantKeyRotator(
            new InMemoryTenantKeyRepository(),
            new PrecomputedKeyPairGenerator([Keys::pair(), Keys::otherPair()]),
            Keys::sealer(),
            [
                new IdTokenJwsKind(
                    new JwtIdTokenIssuer(
                        $this->jwts->documents,
                        new PublicSubjectIdentifierResolver(),
                        new StandardClaimsProvider(),
                        Algorithms::all(),
                        new DateInterval('PT1M'),
                    ),
                ),
                new AccessTokenJwsKind(
                    new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), Algorithms::all(), new DateInterval('PT1M')),
                    $this->clients,
                ),
                new LogoutTokenJwsKind(new FakeLogoutTokenDelivery(new DateInterval('PT4M')), ServedChannels::backChannelOnly()),
            ],
            new DateInterval('PT6M'),
            $clock,
            new RecordingEventDispatcher(),
        );
        $context = RequestContext::unknown($clock->now());
        $first = $rotator->rotate($this->tenant, Algorithms::rs256(), $context);

        // When
        $rotator->rotate($this->tenant, Algorithms::rs256(), $context);

        // Then
        static::assertEquals($clock->now()->add(new DateInterval('PT4M')), $first->retirementDueAt);
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
            accessTokenFormat: AccessTokenFormat::Opaque,
        ));
        $kind = new AccessTokenJwsKind(new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), Algorithms::all()), $this->clients);

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
        $clock = new MockClock(Fixtures::now());
        $repository = new InMemoryTenantKeyRepository();
        $rotator = new TenantKeyRotator(
            $repository,
            new JwtLibraryKeyPairGenerator(Algorithms::everyUse()),
            Keys::sealer(),
            [
                new IdTokenJwsKind(
                    new JwtIdTokenIssuer(
                        $this->jwts->documents,
                        new PublicSubjectIdentifierResolver(),
                        new StandardClaimsProvider(),
                        Algorithms::all(),
                        new DateInterval('PT2M'),
                    ),
                ),
                new AccessTokenJwsKind(
                    new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), Algorithms::all(), new DateInterval('PT2M')),
                    $this->clients,
                ),
                new RequestObjectJweKind(new RequestObjectValidator(new DateInterval('PT10M'), new DateInterval('PT30S'))),
                new PushedRequestJweKind($this->pushedRequests(new DateInterval('PT90S'))),
            ],
            new DateInterval('PT6M'),
            $clock,
            new RecordingEventDispatcher(),
        );
        $context = RequestContext::unknown($clock->now());
        $signing = $rotator->rotate($this->tenant, Algorithms::rs256(), $context);
        $encryption = $rotator->rotate($this->tenant, Algorithms::ecdhEsA256Kw(), $context);

        // When
        $rotator->rotate($this->tenant, Algorithms::rs256(), $context);
        $rotator->rotate($this->tenant, Algorithms::ecdhEsA256Kw(), $context);

        // Then
        static::assertEquals($clock->now()->add(new DateInterval('PT2M')), $signing->retirementDueAt);
        static::assertEquals($clock->now()->add(new DateInterval('PT10M')), $encryption->retirementDueAt);
    }

    private function pushedRequests(DateInterval $lifetime): PushedAuthorizationHandler
    {
        $clock = new MockClock(Fixtures::now());

        return new PushedAuthorizationHandler(
            new ClientAuthenticator($this->clients, Methods::all(new FakePasswordHasher()), $clock, new RecordingEventDispatcher()),
            Proofs::verifier(),
            new Endpoints(),
            new AuthorizationRequestParser($this->clients, ServedModes::queryAndFormPost()),
            RequestObjects::resolver($this->clients, $clock),
            new InMemoryPushedAuthorizationRequestRepository(),
            $clock,
            $lifetime,
        );
    }

    private function documents(DateInterval $lifetime): ResponseDocumentIssuer
    {
        return new ResponseDocumentIssuer($this->jwts->documents, new MockClock(Fixtures::now()), $lifetime);
    }
}
