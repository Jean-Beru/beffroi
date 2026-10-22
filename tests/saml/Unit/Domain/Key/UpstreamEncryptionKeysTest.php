<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Key;

use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Domain\Key\UpstreamEncryptionKeys;
use Beffroi\Saml\Tests\Fixture\SamlEncryption;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-64, S-65, section 6.12 step 1: the keys one upstream identity provider encrypts for, among the keys of
 * the tenant in service, the newest first, and one material the key of one provider only.
 */
final class UpstreamEncryptionKeysTest extends TestCase
{
    private const string PROVIDER = 'https://idp-a.example/metadata';

    private const string OTHER_PROVIDER = 'https://idp-b.example/metadata';

    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
    }

    /**
     * S-65: the keys of the provider, the newest first, which is the order its metadata list their certificates in
     * and the order they are tried in.
     */
    #[Test]
    public function theKeysOfTheProviderComeNewestFirst(): void
    {
        // Given
        $current = SamlKeys::encryptionKey($this->tenant, self::PROVIDER);
        $current->activate(Fixtures::now());
        $next = SamlKeys::encryptionKey($this->tenant, self::PROVIDER, 1, Fixtures::now()->modify('+1 day'));

        // When
        $keys = UpstreamEncryptionKeys::of([$current, $next], self::PROVIDER);

        // Then
        static::assertSame([$next, $current], $keys->keys);
    }

    /**
     * S-64: the keys of another provider, the SAML signing key and the keys of any other algorithm, a key of another
     * type among them, are not the provider's.
     */
    #[Test]
    public function onlyTheKeysOfTheProviderAreItsOwn(): void
    {
        // Given
        $own = SamlKeys::encryptionKey($this->tenant, self::PROVIDER);
        $inService = [
            SamlKeys::activeKey($this->tenant),
            SamlKeys::encryptionKey($this->tenant, self::OTHER_PROVIDER, 1),
            $own,
            SamlKeys::key($this->tenant, Keys::encryptionPair()),
        ];

        // When
        $keys = UpstreamEncryptionKeys::of($inService, self::PROVIDER);

        // Then
        static::assertSame([$own], $keys->keys);
    }

    /**
     * S-64: the algorithm of the keys is the one of the provider, the one its keys are opened under.
     */
    #[Test]
    public function theAlgorithmIsTheOneOfTheProvider(): void
    {
        // Given
        $inService = [SamlKeys::encryptionKey($this->tenant, self::OTHER_PROVIDER, 1), SamlKeys::encryptionKey($this->tenant, self::PROVIDER)];

        // When
        $keys = UpstreamEncryptionKeys::of($inService, self::PROVIDER);

        // Then
        static::assertSame(new SamlEncryption(self::PROVIDER)->name(), $keys->algorithm?->name());
    }

    /**
     * Section 6.13 step 1: a provider for which the tenant holds no key in service has none, and no algorithm.
     */
    #[Test]
    public function aProviderWithoutAKeyHasNone(): void
    {
        // Given
        $inService = [SamlKeys::activeKey($this->tenant), SamlKeys::encryptionKey($this->tenant, self::OTHER_PROVIDER, 1)];

        // When
        $keys = UpstreamEncryptionKeys::of($inService, self::PROVIDER);

        // Then
        static::assertSame([null, []], [$keys->algorithm, $keys->keys]);
    }

    /**
     * S-64: a key of the provider whose modulus another key of the tenant in service holds, the key of another provider
     * or the SAML signing key, is refused, whichever of the two is asked for, naming the two algorithms and not the
     * material.
     *
     * @param list<TenantKey> $inService
     */
    #[Test]
    #[DataProvider('provideSharedMaterials')]
    public function aKeyHoldingTheModulusOfAnotherKeyIsRefused(array $inService, string $provider, string $message): void
    {
        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs($message);

        // When
        UpstreamEncryptionKeys::of($inService, $provider);
    }

    /**
     * @return iterable<string, array{list<TenantKey>, string, string}>
     */
    public static function provideSharedMaterials(): iterable
    {
        $tenant = Fixtures::tenant();
        $first = SamlKeys::encryptionKey($tenant, self::PROVIDER);
        $second = self::sameMaterial(SamlKeys::encryptionKey($tenant, self::OTHER_PROVIDER), 'second');

        yield 'the key of another provider, asked for the first' => [
            [$first, $second],
            self::PROVIDER,
            'A key of SAML-ENCRYPTION:https://idp-a.example/metadata holds the modulus of a key of SAML-ENCRYPTION:https://idp-b.example/metadata: one key belongs to one identity provider (spec/saml.md S-64).',
        ];
        yield 'the key of another provider, asked for the second' => [
            [$first, $second],
            self::OTHER_PROVIDER,
            'A key of SAML-ENCRYPTION:https://idp-b.example/metadata holds the modulus of a key of SAML-ENCRYPTION:https://idp-a.example/metadata: one key belongs to one identity provider (spec/saml.md S-64).',
        ];
        yield 'the SAML signing key' => [
            [SamlKeys::activeKey($tenant), self::sameMaterial(SamlKeys::encryptionKey($tenant, self::PROVIDER), 'signing', SamlKeys::pair()->publicJwk['n'])],
            self::PROVIDER,
            'A key of SAML-ENCRYPTION:https://idp-a.example/metadata holds the modulus of a key of SAML-SIGNING: one key belongs to one identity provider (spec/saml.md S-64).',
        ];
    }

    /**
     * The same key under another "kid", its modulus the one given or the one of the first pair of the providers: what a
     * store that kept the material twice would hold.
     */
    private static function sameMaterial(TenantKey $key, string $kid, ?string $modulus = null): TenantKey
    {
        return new TenantKey(
            $kid,
            $key->tenant,
            $key->algorithm,
            [
                ...$key->publicJwk,
                'kid' => $kid,
                'n' => $modulus ?? SamlKeys::encryptionPair()->publicJwk['n'],
            ],
            $key->sealedPrivateJwk,
            $key->createdAt,
            $key->activationDueAt,
        );
    }
}
