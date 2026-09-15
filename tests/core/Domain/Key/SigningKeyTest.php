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
        $key = self::key();

        static::assertSame(KeyStatus::Active, $key->status);
        static::assertTrue($key->isActive());
        static::assertTrue($key->isPublished());
        static::assertSame('RSA', $key->publicJwk['kty']);
        static::assertSame($key->kid, $key->publicJwk['kid']);
    }

    /**
     * The rotation window: active, then retiring (still published), then retired (gone from the JWK Set).
     */
    #[Test]
    public function itRetiresInTwoSteps(): void
    {
        $key = self::key();
        $t1 = Fixtures::now()->modify('+1 day');
        $t2 = Fixtures::now()->modify('+2 days');

        $key->startRetiring($t1);
        static::assertSame(KeyStatus::Retiring, $key->status);
        static::assertFalse($key->isActive());
        static::assertTrue($key->isPublished());
        static::assertSame($t1, $key->retiringAt);

        $key->retire($t2);
        static::assertSame(KeyStatus::Retired, $key->status);
        static::assertFalse($key->isPublished());
        static::assertSame($t2, $key->retiredAt);
    }

    #[Test]
    public function onlyAnActiveKeyStartsRetiring(): void
    {
        $key = self::key();
        $key->startRetiring(Fixtures::now());

        $this->expectException(LogicException::class);
        $key->startRetiring(Fixtures::now());
    }

    #[Test]
    public function onlyARetiringKeyRetires(): void
    {
        $this->expectException(LogicException::class);

        self::key()->retire(Fixtures::now());
    }

    /**
     * @param array<string, string> $publicJwk
     */
    #[Test]
    #[DataProvider('provideBadPublicJwks')]
    public function thePublicJwkMustDescribeThisKeyAndNothingPrivate(array $publicJwk, string $kid = 'kid'): void
    {
        $this->expectException(InvalidArgumentException::class);

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
        $this->expectException(InvalidArgumentException::class);

        new SigningKey(Keys::pair()->kid, Fixtures::tenant(), SignatureAlgorithm::RS256, Keys::pair()->publicJwk, '', Fixtures::now());
    }

    /**
     * RFC 7517 §5: the JWK Set lists the published keys, public members only.
     */
    #[Test]
    public function thePublicKeySetServesPublishedKeysOnlyAndFindsThemByKid(): void
    {
        $active = self::key();
        $retired = self::key(Keys::otherPair()->kid, Keys::otherPair()->publicJwk);
        $retired->startRetiring(Fixtures::now());
        $retired->retire(Fixtures::now());

        $set = new PublicKeySet([$active, $retired]);

        static::assertFalse($set->isEmpty());
        static::assertSame([$active], $set->keys);
        static::assertSame($active, $set->find($active->kid));
        static::assertNull($set->find($retired->kid));
        static::assertSame([
            'keys' => [$active->publicJwk],
        ], $set->toJwks());
        static::assertArrayNotHasKey('d', $set->toJwks()['keys'][0]);
        static::assertTrue(new PublicKeySet([])->isEmpty());
    }

    /**
     * @param array<string, string>|null $publicJwk
     */
    private static function key(?string $kid = null, ?array $publicJwk = null): SigningKey
    {
        return new SigningKey($kid ?? Keys::pair()->kid, Fixtures::tenant(), SignatureAlgorithm::RS256, $publicJwk ?? Keys::pair()->publicJwk, 'sealed', Fixtures::now());
    }
}
