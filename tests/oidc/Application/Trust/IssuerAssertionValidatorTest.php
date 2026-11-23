<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Trust;

use function array_values;
use DateInterval;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Trust\IssuerAssertionValidator;
use Beffroi\Oidc\Bridge\InMemory\InMemoryIssuerAssertionReplayGuard;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Exception\InvalidGrantException;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeClientJwksFetcher;
use Beffroi\Oidc\Tests\Fixture\FakeTrustedIssuers;
use Beffroi\Oidc\Tests\Fixture\TrustedIssuers;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * RFC 7523 §3
 */
final class IssuerAssertionValidatorTest extends TestCase
{
    private const string REFUSED = 'invalid_grant: The assertion is not one this provider accepts as an authorization (RFC 7523 section 3).';

    private const int COOLDOWN = 300;

    private Tenant $tenant;

    private Client $client;

    private FakeTrustedIssuers $issuers;

    private InMemoryIssuerAssertionReplayGuard $replays;

    private FakeClientJwksFetcher $fetcher;

    private MockClock $clock;

    private IssuerAssertionValidator $validator;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->client = Clients::presentingAssertions($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->issuers = new FakeTrustedIssuers();
        $this->issuers->trust($this->tenant, TrustedIssuers::workforce());
        $this->replays = new InMemoryIssuerAssertionReplayGuard();
        $this->fetcher = new FakeClientJwksFetcher([ClientAssertions::publishedKeys()]);
        $this->clock = new MockClock(Fixtures::now());
        $this->validator = $this->validatorWith();
    }

    /**
     * RFC 7523 §3
     */
    #[Test]
    public function itAcceptsAnAssertionOfATrustedIssuer(): void
    {
        // Given
        $assertion = TrustedIssuers::assertion('employee-42', (string) $this->tenant->issuer, Fixtures::now(), [
            'jti' => 'the-assertion',
        ]);

        // When
        $verified = $this->validator->validate($this->tenant, $this->client, $assertion, Fixtures::now());

        // Then
        static::assertSame('employee-42', $verified->subject);
        static::assertSame(TrustedIssuers::ISSUER, $verified->issuer->issuer);
        static::assertSame('the-assertion', $verified->jti);
        static::assertEquals(Fixtures::now()->modify('+60 seconds'), $verified->expiresAt);
    }

    /**
     * RFC 7523 §3, §4
     */
    #[Test]
    public function itRefusesAnAssertionSpentAlready(): void
    {
        // Given
        $assertion = TrustedIssuers::assertion('employee-42', (string) $this->tenant->issuer, Fixtures::now());
        $this->validator->spend($this->tenant, $this->validator->validate($this->tenant, $this->client, $assertion, Fixtures::now()));
        $verified = $this->validator->validate($this->tenant, $this->client, $assertion, Fixtures::now());

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->validator->spend($this->tenant, $verified);
    }

    /**
     * RFC 7523 §3
     */
    #[Test]
    public function aSpentAssertionIsRememberedUntilTheLastInstantItWouldBeAccepted(): void
    {
        // Given
        $assertion = TrustedIssuers::assertion('employee-42', (string) $this->tenant->issuer, Fixtures::now());
        $verified = $this->validator->validate($this->tenant, $this->client, $assertion, Fixtures::now());

        // When
        $this->validator->spend($this->tenant, $verified);

        // Then
        static::assertEquals([Fixtures::now()->modify('+90 seconds')], array_values($this->replays->seen));
    }

    #[Test]
    public function anAssertionJudgedAndNeverSpentIsAcceptedAgain(): void
    {
        // Given
        $assertion = TrustedIssuers::assertion('employee-42', (string) $this->tenant->issuer, Fixtures::now());
        $this->validator->validate($this->tenant, $this->client, $assertion, Fixtures::now());

        // When
        $verified = $this->validator->validate($this->tenant, $this->client, $assertion, Fixtures::now());

        // Then
        static::assertSame('employee-42', $verified->subject);
    }

    /**
     * RFC 7523 §3
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
     * RFC 7523 §3
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
     * RFC 7523 §3
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
     * RFC 8725 §3.10, RFC 7515 §4.1.1
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
     * RFC 7523 §2.1
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

    /**
     * RFC 7517 §5, RFC 7591 §2
     */
    #[Test]
    public function theKeysOfAnIssuerBehindAUrlAreReadOnceAndKept(): void
    {
        // Given
        $this->trustIssuerPublishingBehindAUrl();
        $this->validator->validate($this->tenant, $this->client, $this->assertionOf('employee-42'), Fixtures::now());

        // When
        $verified = $this->validator->validate($this->tenant, $this->client, $this->assertionOf('employee-43'), Fixtures::now());

        // Then
        static::assertSame('employee-43', $verified->subject);
        static::assertCount(1, $this->fetcher->fetched);
    }

    #[Test]
    public function anAssertionNamingAKeyTheKeptSetDoesNotHoldHasTheSetReadAgain(): void
    {
        // Given
        $this->trustIssuerPublishingBehindAUrl();
        $this->validator->validate($this->tenant, $this->client, $this->assertionOf('employee-42'), Fixtures::now());
        $this->clock->modify('+' . (self::COOLDOWN + 1) . ' seconds');

        // When
        try {
            $this->validator->validate(
                $this->tenant,
                $this->client,
                $this->assertionOf('employee-43', [
                    'kid' => 'rotated-in',
                ]),
                Fixtures::now(),
            );
        } catch (InvalidGrantException) {
        }

        // Then
        static::assertCount(2, $this->fetcher->fetched);
    }

    /**
     * RFC 7523 §3
     */
    #[Test]
    public function anIssuerWhoseKeysCannotBeReadIsTheOneRefusal(): void
    {
        // Given
        $this->trustIssuerPublishingBehindAUrl();
        $this->fetcher->failure = new ClientKeysUnavailableException('https://workforce.example.com/jwks answered 500.');

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->validator->validate($this->tenant, $this->client, $this->assertionOf('employee-42'), Fixtures::now());
    }

    /**
     * @param array<string, mixed> $header
     */
    private function assertionOf(string $subject, array $header = []): string
    {
        return TrustedIssuers::assertion(
            $subject,
            (string) $this->tenant->issuer,
            Fixtures::now(),
            [
                'jti' => 'assertion-of-' . $subject,
            ],
            $header,
        );
    }

    private function validatorWith(): IssuerAssertionValidator
    {
        return TrustedIssuers::validator($this->issuers, $this->replays, $this->fetcher, $this->clock, new DateInterval('PT' . self::COOLDOWN . 'S'));
    }

    /**
     * RFC 7517 §5
     */
    private function trustIssuerPublishingBehindAUrl(): void
    {
        $this->issuers->trust($this->tenant, TrustedIssuers::workforce(keys: new ClientUri(TrustedIssuers::JWKS_URI)));
    }
}
