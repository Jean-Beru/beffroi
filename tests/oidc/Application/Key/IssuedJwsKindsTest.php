<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Key;

use DateInterval;
use Heidi\Core\Application\Key\SigningKeyRotator;
use Heidi\Core\Bridge\InMemory\InMemorySigningKeyRepository;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use Heidi\Core\Tests\Fixture\PrecomputedKeyPairGenerator;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Authorization\ResponseDocumentIssuer;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Key\AccessTokenJwsKind;
use Heidi\Oidc\Application\Key\IdTokenJwsKind;
use Heidi\Oidc\Application\Key\ResponseDocumentJwsKind;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\ServedModes;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Architecture §3.3: the kinds of JWS the module issues, as the rotation of the core reads them to date
 * the retirement of a key.
 */
final class IssuedJwsKindsTest extends TestCase
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
        $kind = new IdTokenJwsKind(new JwtIdTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), new StandardClaimsProvider(), Algorithms::all(), new DateInterval('PT1H')));

        // When / Then
        static::assertEquals(new DateInterval('PT1H'), $kind->longestLifetime($this->tenant));
    }

    #[Test]
    public function theSelfContainedAccessTokenLivesAsLongAsItsIssuerSaysWhenAClientReceivesIt(): void
    {
        // Given
        $this->clients->save(Clients::public($this->tenant));
        $kind = new AccessTokenJwsKind(new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), Algorithms::all(), new DateInterval('PT20M')), $this->clients);

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
        $rotator = new SigningKeyRotator(
            new InMemorySigningKeyRepository(),
            new PrecomputedKeyPairGenerator([Keys::pair(), Keys::otherPair()]),
            Keys::sealer(),
            [
                new IdTokenJwsKind(new JwtIdTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), new StandardClaimsProvider(), Algorithms::all(), new DateInterval('PT2M'))),
                new AccessTokenJwsKind(new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), Algorithms::all(), new DateInterval('PT2M')), $this->clients),
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
     * An opaque access token depends on no key: a tenant whose clients all receive one issues no such JWS.
     */
    #[Test]
    public function theSelfContainedAccessTokenIsNotIssuedWhenEveryClientReceivesAnOpaqueOne(): void
    {
        // Given
        $this->clients->save(Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), accessTokenFormat: AccessTokenFormat::Opaque));
        $kind = new AccessTokenJwsKind(new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), Algorithms::all()), $this->clients);

        // When / Then
        static::assertNull($kind->longestLifetime($this->tenant));
    }

    private function documents(DateInterval $lifetime): ResponseDocumentIssuer
    {
        return new ResponseDocumentIssuer($this->jwts->signer, Algorithms::all(), new MockClock(Fixtures::now()), $lifetime);
    }
}
