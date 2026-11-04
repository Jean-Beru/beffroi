<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Bridge\Configuration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationTrustedIssuers;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\TrustedIssuers;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §5.1
 */
final class ConfigurationTrustedIssuersTest extends TestCase
{
    /**
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
     * RFC 7523 §3
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
        static::assertInstanceOf(ClientJwks::class, $issuer->keys);
        static::assertCount(1, $issuer->keys->keys);
    }

    /**
     * RFC 7517 §5
     */
    #[Test]
    public function anIssuerMayPublishItsKeysBehindAUrl(): void
    {
        // Given
        $issuers = $this->issuers([
            TrustedIssuers::ISSUER =>
                [
                    'jwks_uri' => TrustedIssuers::JWKS_URI,
                ] + self::withoutKeys(),
        ]);

        // When
        $issuer = $issuers->find($this->tenant, TrustedIssuers::ISSUER) ?? static::fail('The declared issuer should have been found.');

        // Then
        static::assertInstanceOf(ClientUri::class, $issuer->keys);
        static::assertSame(TrustedIssuers::JWKS_URI, $issuer->keys->value);
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
            self::withoutKeys(),
            'publishes the keys it signs with in "jwks" or behind a "jwks_uri"',
        ];
        yield 'keys both ways' => [
            [
                'jwks_uri' => TrustedIssuers::JWKS_URI,
            ] + self::WORKFORCE,
            'either in "jwks" or behind a "jwks_uri", never both',
        ];
        yield 'a jwks_uri that is not a URL' => [
            [
                'jwks_uri' => 'not-a-url',
            ] + self::withoutKeys(),
            'is not an absolute URI',
        ];
        yield 'a jwks_uri in plain HTTP' => [
            [
                'jwks_uri' => 'http://workforce.example.com/jwks',
            ] + self::withoutKeys(),
            'must use HTTPS',
        ];
        yield 'a jwks_uri that is not a string' => [
            [
                'jwks_uri' => ['https://workforce.example.com/jwks'],
            ] + self::withoutKeys(),
            'jwks_uri option of the trusted issuer',
        ];
        yield 'keys that are not written as a set' => [
            [
                'jwks' => 'not-a-set',
            ] + self::withoutKeys(),
            'jwks option of the trusted issuer',
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
     * @return array<string, mixed>
     */
    private static function withoutKeys(): array
    {
        return [
            'signing_algorithms' => ['ES256'],
            'clients' => ['job-runner'],
            'identity_provider' => 'workforce',
            'trusted_scopes' => ['invoices.read'],
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
