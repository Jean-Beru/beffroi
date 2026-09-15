<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Key;

use Heidi\Core\Domain\Key\KeyStatus;
use Heidi\Core\Domain\Key\PublicKeySet;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class SigningKeyTest extends TestCase
{
    #[Test]
    public function aNewKeyIsActiveAndPublished(): void
    {
        // When
        $key = self::key();

        // Then
        static::assertSame(KeyStatus::Active, $key->status);
        static::assertTrue($key->isActive());
        static::assertTrue($key->isPublished());
    }

    #[Test]
    public function itsPublicJwkIsTheRsaKeyNamedByItsKid(): void
    {
        // When
        $key = self::key();

        // Then
        static::assertSame('RSA', $key->publicJwk['kty']);
        static::assertSame($key->kid, $key->publicJwk['kid']);
    }

    /**
     * The rotation window: active, then retiring, still published.
     */
    #[Test]
    public function aRetiringKeyIsNoLongerActiveButStillPublished(): void
    {
        // Given
        $key = self::key();
        $retiringAt = Fixtures::now()->modify('+1 day');

        // When
        $key->startRetiring($retiringAt);

        // Then
        static::assertSame(KeyStatus::Retiring, $key->status);
        static::assertFalse($key->isActive());
        static::assertTrue($key->isPublished());
        static::assertSame($retiringAt, $key->retiringAt);
    }

    /**
     * The rotation window: retiring, then retired, gone from the JWK Set.
     */
    #[Test]
    public function aRetiredKeyIsNoLongerPublished(): void
    {
        // Given
        $key = self::key();
        $key->startRetiring(Fixtures::now()->modify('+1 day'));
        $retiredAt = Fixtures::now()->modify('+2 days');

        // When
        $key->retire($retiredAt);

        // Then
        static::assertSame(KeyStatus::Retired, $key->status);
        static::assertFalse($key->isPublished());
        static::assertSame($retiredAt, $key->retiredAt);
    }

    #[Test]
    public function onlyAnActiveKeyStartsRetiring(): void
    {
        // Given
        $key = self::key();
        $key->startRetiring(Fixtures::now());

        // Then
        $this->expectException(LogicException::class);

        // When
        $key->startRetiring(Fixtures::now());
    }

    #[Test]
    public function onlyARetiringKeyRetires(): void
    {
        // Given
        $key = self::key();

        // Then
        $this->expectException(LogicException::class);

        // When
        $key->retire(Fixtures::now());
    }

    /**
     * @param array<string, string> $publicJwk
     */
    #[Test]
    #[DataProvider('provideBadPublicJwks')]
    public function thePublicJwkMustDescribeThisKeyAndNothingPrivate(array $publicJwk, string $kid = 'kid'): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new SigningKey($kid, Fixtures::tenant(), SignatureAlgorithm::RS256, $publicJwk, 'sealed', Fixtures::now());
    }

    /**
     * @return iterable<string, array{array<string, string>}|array{array<string, string>, string}>
     */
    public static function provideBadPublicJwks(): iterable
    {
        $good = Keys::pair()->publicJwk;
        yield 'kid mismatch' => [$good, 'another-kid'];
        yield 'missing alg' => [[
            'kty' => 'RSA',
            'kid' => $good['kid'],
            'use' => 'sig',
            'n' => $good['n'],
            'e' => $good['e'],
        ], $good['kid']];
        yield 'wrong use' => [[
            ...$good,
            'use' => 'enc',
        ], $good['kid']];
        yield 'wrong key type' => [[
            ...$good,
            'kty' => 'EC',
        ], $good['kid']];
        yield 'private exponent present' => [[
            ...$good,
            'd' => 'secret',
        ], $good['kid']];
        yield 'empty kid' => [[
            ...$good,
            'kid' => '',
        ], ''];
    }

    #[Test]
    public function itCarriesItsSealedPrivateMaterial(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new SigningKey(Keys::pair()->kid, Fixtures::tenant(), SignatureAlgorithm::RS256, Keys::pair()->publicJwk, '', Fixtures::now());
    }

    /**
     * RFC 7517 §5: the JWK Set lists the published keys only.
     */
    #[Test]
    public function thePublicKeySetServesPublishedKeysOnly(): void
    {
        // Given
        $active = self::key();
        $retired = self::retiredKey();

        // When
        $set = new PublicKeySet([$active, $retired]);

        // Then
        static::assertFalse($set->isEmpty());
        static::assertSame([$active], $set->keys);
        static::assertSame([
            'keys' => [$active->publicJwk],
        ], $set->toJwks());
    }

    #[Test]
    public function thePublicKeySetFindsAPublishedKeyByKid(): void
    {
        // Given
        $active = self::key();
        $set = new PublicKeySet([$active, self::retiredKey()]);

        // When / Then
        static::assertSame($active, $set->find($active->kid));
    }

    #[Test]
    public function thePublicKeySetDoesNotFindARetiredKey(): void
    {
        // Given
        $retired = self::retiredKey();
        $set = new PublicKeySet([self::key(), $retired]);

        // When / Then
        static::assertNull($set->find($retired->kid));
    }

    /**
     * RFC 7517 §5: public members only.
     */
    #[Test]
    public function theJwksCarriesNoPrivateMember(): void
    {
        // Given
        $set = new PublicKeySet([self::key()]);

        // When
        $jwks = $set->toJwks();

        // Then
        static::assertArrayNotHasKey('d', $jwks['keys'][0]);
    }

    #[Test]
    public function aPublicKeySetWithoutKeysIsEmpty(): void
    {
        // When / Then
        static::assertTrue(new PublicKeySet([])->isEmpty());
    }

    /**
     * @param array<string, string>|null $publicJwk
     */
    private static function key(?string $kid = null, ?array $publicJwk = null): SigningKey
    {
        return new SigningKey($kid ?? Keys::pair()->kid, Fixtures::tenant(), SignatureAlgorithm::RS256, $publicJwk ?? Keys::pair()->publicJwk, 'sealed', Fixtures::now());
    }

    private static function retiredKey(): SigningKey
    {
        $key = self::key(Keys::otherPair()->kid, Keys::otherPair()->publicJwk);
        $key->startRetiring(Fixtures::now());
        $key->retire(Fixtures::now());

        return $key;
    }
}
