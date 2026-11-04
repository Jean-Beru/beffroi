<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use DateInterval;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\Registration\SoftwareStatementVerifier;
use Beffroi\Oidc\Bridge\InMemory\InMemorySoftwareStatementReplayGuard;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Exception\InvalidSoftwareStatementException;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\Policies;
use Beffroi\Oidc\Tests\Fixture\SoftwareStatements;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7591 §2.3, Decision 0006
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
     * RFC 7591 §2.3
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
     * RFC 7591 §2.3
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
     * RFC 8725 §3.10
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
     * RFC 7515 §4.1.1
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
     * Decision 0006
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
