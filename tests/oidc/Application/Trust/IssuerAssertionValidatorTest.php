<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Trust;

use DateInterval;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Trust\IssuerAssertionValidator;
use Heidi\Oidc\Bridge\InMemory\InMemoryIssuerAssertionReplayGuard;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Exception\InvalidGrantException;
use Heidi\Oidc\Tests\Fixture\ClientAssertions;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeTrustedIssuers;
use Heidi\Oidc\Tests\Fixture\TrustedIssuers;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * What an assertion presented as an authorization has to say (RFC 7523 §3). Every refusal is the same refusal:
 * a grant that mints a user teaches nothing about what the tenant trusts.
 */
final class IssuerAssertionValidatorTest extends TestCase
{
    private const string REFUSED = 'invalid_grant: The assertion is not one this provider accepts as an authorization (RFC 7523 section 3).';

    private Tenant $tenant;

    private Client $client;

    private FakeTrustedIssuers $issuers;

    private InMemoryIssuerAssertionReplayGuard $replays;

    private IssuerAssertionValidator $validator;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->client = Clients::presentingAssertions($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->issuers = new FakeTrustedIssuers();
        $this->issuers->trust($this->tenant, TrustedIssuers::workforce());
        $this->replays = new InMemoryIssuerAssertionReplayGuard();
        $this->validator = $this->validatorWith();
    }

    /**
     * RFC 7523 §3: signed by an issuer the tenant trusts, addressed to this provider, still valid, and about
     * somebody.
     */
    #[Test]
    public function itAcceptsAnAssertionOfATrustedIssuer(): void
    {
        // Given
        $assertion = TrustedIssuers::assertion('employee-42', (string) $this->tenant->issuer, Fixtures::now());

        // When
        $verified = $this->validator->validate($this->tenant, $this->client, $assertion, Fixtures::now());

        // Then
        static::assertSame('employee-42', $verified->subject);
        static::assertSame(TrustedIssuers::ISSUER, $verified->issuer->issuer);
    }

    /**
     * RFC 7523 §3, §4: one assertion is exchanged once.
     */
    #[Test]
    public function itRefusesAnAssertionPresentedTwice(): void
    {
        // Given
        $assertion = TrustedIssuers::assertion('employee-42', (string) $this->tenant->issuer, Fixtures::now());
        $this->validator->validate($this->tenant, $this->client, $assertion, Fixtures::now());

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->validator->validate($this->tenant, $this->client, $assertion, Fixtures::now());
    }

    /**
     * RFC 7523 §3: an issuer one tenant trusts is unknown to another.
     */
    #[Test]
    public function anIssuerTrustedByOneTenantIsUnknownToAnother(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $client = Clients::presentingAssertions($other, new FakePasswordHasher()->hash(Clients::SECRET));
        $assertion = TrustedIssuers::assertion('employee-42', (string) $other->issuer, Fixtures::now());

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->validator->validate($other, $client, $assertion, Fixtures::now());
    }

    /**
     * RFC 7523 §3: an issuer trusted for one client is not thereby trusted for every client of the tenant.
     */
    #[Test]
    public function itRefusesAnAssertionPresentedByAClientTheIssuerIsNotTrustedFor(): void
    {
        // Given
        $other = Clients::presentingAssertions($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), 'another-runner');
        $assertion = TrustedIssuers::assertion('employee-42', (string) $this->tenant->issuer, Fixtures::now());

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->validator->validate($this->tenant, $other, $assertion, Fixtures::now());
    }

    /**
     * RFC 7523 §3: an assertion this provider does not accept is refused with one answer, whatever is wrong
     * with it.
     *
     * @param callable(Tenant): string $assertion
     */
    #[Test]
    #[DataProvider('provideAssertionsThatAreRefused')]
    public function itRefusesAnAssertionThatDoesNotHoldTogether(callable $assertion): void
    {
        // Given
        $tenant = $this->tenant;

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->validator->validate($tenant, $this->client, $assertion($tenant), Fixtures::now());
    }

    /**
     * @return iterable<string, array{callable(Tenant): string}>
     */
    public static function provideAssertionsThatAreRefused(): iterable
    {
        yield 'not a compact JWT' => [static fn (Tenant $tenant): string => 'not-a-jwt'];
        yield 'an unknown issuer' => [
            static fn (Tenant $tenant): string => TrustedIssuers::assertion('employee-42', (string) $tenant->issuer, Fixtures::now(), [
                'iss' => 'https://somebody-else.example',
            ]),
        ];
        yield 'no issuer at all' => [
            static fn (Tenant $tenant): string => ClientAssertions::signedWithKey([
                'sub' => 'employee-42',
                'aud' => (string) $tenant->issuer,
                'exp' => Fixtures::now()->getTimestamp() + 60,
                'iat' => Fixtures::now()->getTimestamp(),
                'jti' => 'no-issuer',
            ]),
        ];
        yield 'a signature of another key' => [
            static fn (Tenant $tenant): string => ClientAssertions::signedWithKey(
                TrustedIssuers::claims('employee-42', (string) $tenant->issuer, Fixtures::now()),
                key: Algorithms::es256()->generateKey(),
            ),
        ];
        yield 'an audience that is not this provider' => [
            static fn (Tenant $tenant): string => TrustedIssuers::assertion('employee-42', 'https://somebody-else.example', Fixtures::now()),
        ];
        yield 'this provider and somebody else' => [
            static fn (Tenant $tenant): string => TrustedIssuers::assertion('employee-42', (string) $tenant->issuer, Fixtures::now(), [
                'aud' => [(string) $tenant->issuer, 'https://somebody-else.example'],
            ]),
        ];
        yield 'expired' => [
            static fn (Tenant $tenant): string => TrustedIssuers::assertion('employee-42', (string) $tenant->issuer, Fixtures::now(), [
                'exp' => Fixtures::now()->getTimestamp() - 3600,
            ]),
        ];
        yield 'no expiry' => [
            static fn (Tenant $tenant): string => TrustedIssuers::assertion('employee-42', (string) $tenant->issuer, Fixtures::now(), [
                'exp' => null,
            ]),
        ];
        yield 'an expiry beyond what this provider accepts' => [
            static fn (Tenant $tenant): string => TrustedIssuers::assertion('employee-42', (string) $tenant->issuer, Fixtures::now(), [
                'exp' => Fixtures::now()->getTimestamp() + 86400,
            ]),
        ];
        yield 'issued in the future' => [
            static fn (Tenant $tenant): string => TrustedIssuers::assertion('employee-42', (string) $tenant->issuer, Fixtures::now(), [
                'iat' => Fixtures::now()->getTimestamp() + 3600,
            ]),
        ];
        yield 'no iat' => [
            static fn (Tenant $tenant): string => TrustedIssuers::assertion('employee-42', (string) $tenant->issuer, Fixtures::now(), [
                'iat' => null,
            ]),
        ];
        yield 'no jti' => [
            static fn (Tenant $tenant): string => TrustedIssuers::assertion('employee-42', (string) $tenant->issuer, Fixtures::now(), [
                'jti' => null,
            ]),
        ];
        yield 'about nobody' => [
            static fn (Tenant $tenant): string => TrustedIssuers::assertion('employee-42', (string) $tenant->issuer, Fixtures::now(), [
                'sub' => null,
            ]),
        ];
    }

    /**
     * RFC 8725 §3.10, RFC 7515 §4.1.1: an algorithm the tenant did not trust the issuer to sign with is refused
     * even though the key is the right one.
     */
    #[Test]
    public function itRefusesAnAlgorithmTheIssuerIsNotTrustedToSignWith(): void
    {
        // Given
        $this->issuers->trust($this->tenant, TrustedIssuers::workforce(signingAlgorithms: ['RS256']));
        $assertion = TrustedIssuers::assertion('employee-42', (string) $this->tenant->issuer, Fixtures::now());

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->validator->validate($this->tenant, $this->client, $assertion, Fixtures::now());
    }

    /**
     * RFC 7523 §2.1: an assertion that authenticates a client is not one that authorizes it. The "iss" of one
     * names the client, which no trusted issuer of this tenant is.
     */
    #[Test]
    public function anAssertionThatAuthenticatesAClientIsNotAcceptedAsAnAuthorization(): void
    {
        // Given
        $assertion = ClientAssertions::signedWithKey(ClientAssertions::claims('job-runner', (string) $this->tenant->issuer, Fixtures::now()));

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->validator->validate($this->tenant, $this->client, $assertion, Fixtures::now());
    }

    private function validatorWith(): IssuerAssertionValidator
    {
        return new IssuerAssertionValidator(
            new JwtLibraryCompactJwtReader(),
            new JwtLibraryJwtKeyVerifier(Algorithms::all()->manager()),
            $this->issuers,
            $this->replays,
            new DateInterval('PT300S'),
            new DateInterval('PT30S'),
        );
    }
}
