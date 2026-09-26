<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Bridge\Configuration;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Bridge\Configuration\ConfigurationTrustedIssuers;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\TrustedIssuers;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The third parties declared in the configuration (architecture §5.1), validated at boot: a tenant that
 * declares an issuer it cannot read learns it when the deployment starts.
 */
final class ConfigurationTrustedIssuersTest extends TestCase
{
    /**
     * The public key of the issuer, as the tenant puts it in its configuration.
     *
     * @var array<string, mixed>
     */
    private const array JWKS = [
        'keys' => [[
            'kty' => 'EC',
            'crv' => 'P-256',
            'kid' => 'one',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]],
    ];

    /**
     * @var array<string, mixed>
     */
    private const array WORKFORCE = [
        'jwks' => self::JWKS,
        'signing_algorithms' => ['ES256'],
        'clients' => ['job-runner'],
        'identity_provider' => 'workforce',
        'trusted_scopes' => ['invoices.read'],
    ];

    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
    }

    /**
     * RFC 7523 §3: what the tenant declared is what the issuer is, read as it is written.
     */
    #[Test]
    public function aDeclaredIssuerIsReadAsItIsWritten(): void
    {
        // Given
        $issuers = $this->issuers([
            TrustedIssuers::ISSUER => self::WORKFORCE,
        ]);

        // When
        $issuer = $issuers->find($this->tenant, TrustedIssuers::ISSUER) ?? static::fail('The declared issuer should have been found.');

        // Then
        static::assertSame(TrustedIssuers::ISSUER, $issuer->issuer);
        static::assertSame(['ES256'], $issuer->signingAlgorithms);
        static::assertSame(['job-runner'], $issuer->clientIds);
        static::assertSame('workforce', $issuer->identityProvider);
        static::assertTrue($issuer->isTrustedFor(new Scopes([new Scope('invoices.read')])));
        static::assertCount(1, $issuer->keys->keys);
    }

    #[Test]
    public function anIssuerNobodyDeclaredIsUnknown(): void
    {
        // Given
        $issuers = $this->issuers([
            TrustedIssuers::ISSUER => self::WORKFORCE,
        ]);

        // When / Then
        static::assertNull($issuers->find($this->tenant, 'https://somebody-else.example'));
    }

    /**
     * An issuer one tenant trusts is unknown to another, which is what keeps one deployment's trust from
     * being another's.
     */
    #[Test]
    public function anIssuerOfAnotherTenantIsUnknownHere(): void
    {
        // Given
        $issuers = $this->issuers([
            TrustedIssuers::ISSUER => self::WORKFORCE,
        ]);

        // When / Then
        static::assertNull($issuers->find(Fixtures::tenant('other', 'https://id.other.example'), TrustedIssuers::ISSUER));
    }

    /**
     * @param array<string, mixed> $definition
     */
    #[Test]
    #[DataProvider('provideDeclarationsThatFailAtBoot')]
    public function aWrongDeclarationFailsAtBoot(array $definition, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        $this->issuers([
            TrustedIssuers::ISSUER => $definition,
        ]);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideDeclarationsThatFailAtBoot(): iterable
    {
        yield 'an unknown key' => [
            self::WORKFORCE
                + [
                    'insecure_accept_anything' => true,
                ],
            'has unknown keys: insecure_accept_anything',
        ];
        yield 'no keys at all' => [
            [
                'signing_algorithms' => ['ES256'],
                'clients' => ['job-runner'],
                'identity_provider' => 'workforce',
                'trusted_scopes' => ['invoices.read'],
            ],
            'publishes the keys it signs with in "jwks"',
        ];
        yield 'keys that are not a JWK Set' => [
            [
                'jwks' => ['no'],
                'signing_algorithms' => ['ES256'],
                'clients' => ['job-runner'],
                'identity_provider' => 'workforce',
                'trusted_scopes' => ['invoices.read'],
            ],
            'object with a "keys" member',
        ];
        yield 'a symmetric key' => [
            [
                'jwks' => [
                    'keys' => [[
                        'kty' => 'oct',
                        'k' => 'AAAA',
                    ]],
                    'trusted_scopes' => ['invoices.read'],
                ],
                'signing_algorithms' => ['ES256'],
                'clients' => ['job-runner'],
                'identity_provider' => 'workforce',
            ],
            'symmetric key in a JWK Set is refused',
        ];
        yield 'an algorithm nothing verifies' => [
            [
                'jwks' => self::JWKS,
                'signing_algorithms' => ['HS256'],
                'clients' => ['job-runner'],
                'identity_provider' => 'workforce',
                'trusted_scopes' => ['invoices.read'],
            ],
            'which this provider does not verify',
        ];
        yield 'no algorithm at all' => [
            [
                'jwks' => self::JWKS,
                'signing_algorithms' => [],
                'clients' => ['job-runner'],
                'identity_provider' => 'workforce',
                'trusted_scopes' => ['invoices.read'],
            ],
            'names at least one signing algorithm',
        ];
        yield 'no client' => [
            [
                'jwks' => self::JWKS,
                'signing_algorithms' => ['ES256'],
                'clients' => [],
                'identity_provider' => 'workforce',
                'trusted_scopes' => ['invoices.read'],
            ],
            'names at least one client that may present its assertions',
        ];
        yield 'no scope at all' => [
            [
                'jwks' => self::JWKS,
                'signing_algorithms' => ['ES256'],
                'clients' => ['job-runner'],
                'identity_provider' => 'workforce',
            ],
            'is trusted for at least one scope',
        ];
        yield 'no source of identities' => [
            [
                'jwks' => self::JWKS,
                'signing_algorithms' => ['ES256'],
                'clients' => ['job-runner'],
                'trusted_scopes' => ['invoices.read'],
            ],
            'identity_provider option of the trusted issuer',
        ];
        yield 'clients that are not a list of strings' => [
            [
                'jwks' => self::JWKS,
                'signing_algorithms' => ['ES256'],
                'clients' => 'job-runner',
                'identity_provider' => 'workforce',
                'trusted_scopes' => ['invoices.read'],
            ],
            'clients option of the trusted issuer',
        ];
    }

    /**
     * @param array<string, array<string, mixed>> $definitions
     */
    private function issuers(array $definitions): ConfigurationTrustedIssuers
    {
        return new ConfigurationTrustedIssuers($this->tenant->slug, $definitions, Algorithms::all());
    }
}
