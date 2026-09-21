<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Key;

use DateInterval;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Key\AccessTokenJwsKind;
use Heidi\Oidc\Application\Key\IdTokenJwsKind;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Jwts;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

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
}
