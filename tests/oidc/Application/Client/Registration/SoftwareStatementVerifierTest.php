<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client\Registration;

use DateInterval;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Client\Registration\SoftwareStatementVerifier;
use Heidi\Oidc\Bridge\InMemory\InMemorySoftwareStatementReplayGuard;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Heidi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Heidi\Oidc\Exception\InvalidSoftwareStatementException;
use Heidi\Oidc\Tests\Fixture\ClientAssertions;
use Heidi\Oidc\Tests\Fixture\Policies;
use Heidi\Oidc\Tests\Fixture\SoftwareStatements;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7591 §2.3: what a software statement has to say before any of it is read as metadata. Every refusal
 * is the same refusal, so whoever presents one learns that it was not accepted and nothing else
 * (decision 0006).
 */
final class SoftwareStatementVerifierTest extends TestCase
{
    private const string REFUSED = 'The software_statement is not one this tenant accepts (RFC 7591 section 2.3).';

    private Tenant $tenant;

    private ClientRegistrationPolicy $policy;

    private SoftwareStatementVerifier $verifier;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->policy = Policies::attested([SoftwareStatements::authority()]);
        $this->verifier = self::verifier();
    }

    /**
     * §2.3: signed by an authority the tenant pinned, with a key it holds, addressed here and still valid.
     */
    #[Test]
    public function itAcceptsAStatementOfAPinnedAuthority(): void
    {
        // Given
        $statement = SoftwareStatements::statement((string) $this->tenant->issuer, Fixtures::now());

        // When
        $members = $this->verifier->verify($this->tenant, $this->policy, $statement, Fixtures::now());

        // Then
        static::assertSame('Invoice reader, attested', $members->members()['client_name']);
    }

    /**
     * A tenant that pins no authority has the mode closed rather than open to whoever signs.
     */
    #[Test]
    public function itRefusesEveryStatementOfATenantThatPinsNobody(): void
    {
        // Given
        $statement = SoftwareStatements::statement((string) $this->tenant->issuer, Fixtures::now());

        // Then
        $this->expectException(InvalidSoftwareStatementException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->verifier->verify($this->tenant, Policies::attested(), $statement, Fixtures::now());
    }

    /**
     * §2.3: the authority is the one the tenant pinned by that name, compared byte for byte.
     */
    #[Test]
    public function itRefusesAStatementOfAnAuthorityTheTenantNamesNot(): void
    {
        // Given
        $statement = SoftwareStatements::statement((string) $this->tenant->issuer, Fixtures::now(), [
            'iss' => 'https://another-store.example.com',
        ]);

        // Then
        $this->expectException(InvalidSoftwareStatementException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->verifier->verify($this->tenant, $this->policy, $statement, Fixtures::now());
    }

    /**
     * RFC 8725 §3.10, the whole point of pinning: a statement verified against a key it carries itself
     * proves that whoever wrote it holds a key, which is what anybody holds. The signature below is valid
     * and the key is not the tenant's, so it is refused.
     */
    #[Test]
    public function itRefusesAStatementSignedWithAKeyTheTenantDidNotPin(): void
    {
        // Given
        $elsewhere = new JWK([...Algorithms::es256()->generateKey()->all(), 'kid' => ClientAssertions::KEY_ID]);
        $statement = SoftwareStatements::statement((string) $this->tenant->issuer, Fixtures::now(), key: $elsewhere);

        // Then
        $this->expectException(InvalidSoftwareStatementException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->verifier->verify($this->tenant, $this->policy, $statement, Fixtures::now());
    }

    /**
     * RFC 7515 §4.1.1: an authority signs with what it was pinned to sign with and no other algorithm.
     */
    #[Test]
    public function itRefusesAStatementSignedWithAnAlgorithmTheAuthorityIsNotPinnedFor(): void
    {
        // Given
        $policy = Policies::attested([SoftwareStatements::authority(['RS256'])]);
        $statement = SoftwareStatements::statement((string) $this->tenant->issuer, Fixtures::now());

        // Then
        $this->expectException(InvalidSoftwareStatementException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->verifier->verify($this->tenant, $policy, $statement, Fixtures::now());
    }

    /**
     * A statement an authority signed for another provider is one this one was never given.
     */
    #[Test]
    public function itRefusesAStatementAddressedElsewhere(): void
    {
        // Given
        $statement = SoftwareStatements::statement('https://id.other.example', Fixtures::now());

        // Then
        $this->expectException(InvalidSoftwareStatementException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->verifier->verify($this->tenant, $this->policy, $statement, Fixtures::now());
    }

    /**
     * Decision 0006: a statement with no "exp" would be a registration credential for ever, and one past
     * its "exp" is one whose authority stopped answering for it.
     */
    #[Test]
    public function itRefusesAStatementThatHasExpired(): void
    {
        // Given
        $statement = SoftwareStatements::statement((string) $this->tenant->issuer, Fixtures::now(), [
            'exp' => Fixtures::now()->getTimestamp() - 3600,
        ]);

        // Then
        $this->expectException(InvalidSoftwareStatementException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->verifier->verify($this->tenant, $this->policy, $statement, Fixtures::now());
    }

    /**
     * And one signed for longer than the tenant allows is a bearer credential its authority cannot take
     * back, whatever it wrote in it.
     */
    #[Test]
    public function itRefusesAStatementSignedForLongerThanTheTenantAllows(): void
    {
        // Given
        $statement = SoftwareStatements::statement((string) $this->tenant->issuer, Fixtures::now(), [
            'exp' => Fixtures::now()->getTimestamp() + 86400,
        ]);

        // Then
        $this->expectException(InvalidSoftwareStatementException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->verifier->verify($this->tenant, $this->policy, $statement, Fixtures::now());
    }

    /**
     * One statement registers one client: what is remembered is its "jti", until it expires.
     */
    #[Test]
    public function itRefusesAStatementPresentedTwice(): void
    {
        // Given
        $statement = SoftwareStatements::statement((string) $this->tenant->issuer, Fixtures::now());
        $this->verifier->verify($this->tenant, $this->policy, $statement, Fixtures::now());

        // Then
        $this->expectException(InvalidSoftwareStatementException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->verifier->verify($this->tenant, $this->policy, $statement, Fixtures::now());
    }

    /**
     * A statement with no identifier is one nothing can be remembered of, so it could be presented for
     * ever.
     */
    #[Test]
    public function itRefusesAStatementThatCarriesNoIdentifier(): void
    {
        // Given
        $statement = SoftwareStatements::statement((string) $this->tenant->issuer, Fixtures::now(), [
            'jti' => null,
        ]);

        // Then
        $this->expectException(InvalidSoftwareStatementException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->verifier->verify($this->tenant, $this->policy, $statement, Fixtures::now());
    }

    /**
     * A value that is no compact JWS at all is refused where every other one is, and says nothing more.
     */
    #[Test]
    public function itRefusesAValueThatIsNoStatementAtAll(): void
    {
        // Then
        $this->expectException(InvalidSoftwareStatementException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->verifier->verify($this->tenant, $this->policy, 'not-a-jws', Fixtures::now());
    }

    private static function verifier(): SoftwareStatementVerifier
    {
        return new SoftwareStatementVerifier(
            new JwtLibraryCompactJwtReader(),
            new JwtLibraryJwtKeyVerifier(Algorithms::all()->manager()),
            new InMemorySoftwareStatementReplayGuard(),
            new DateInterval('PT5M'),
            new DateInterval('PT30S'),
        );
    }
}
