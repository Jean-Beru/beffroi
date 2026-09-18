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
    /**
     * OIDC Core §10.1.1: the key is published before it signs, so that a relying party caching the JWK Set
     * learns it.
     */
    #[Test]
    public function aNewKeyIsStagedPublishedAndNotActive(): void
    {
        // When
        $key = self::key();

        // Then
        static::assertSame(KeyStatus::Staged, $key->status);
        static::assertTrue($key->isStaged());
        static::assertFalse($key->isActive());
        static::assertTrue($key->isPublished());
        static::assertNull($key->activatedAt);
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
     * The staging window ends: staged, then active.
     */
    #[Test]
    public function anActivatedKeyIsActiveAndPublished(): void
    {
        // Given
        $key = self::key();
        $activatedAt = Fixtures::now()->modify('+6 minutes');

        // When
        $key->activate($activatedAt);

        // Then
        static::assertSame(KeyStatus::Active, $key->status);
        static::assertTrue($key->isActive());
        static::assertTrue($key->isPublished());
        static::assertSame($activatedAt, $key->activatedAt);
    }

    #[Test]
    public function onlyAStagedKeyActivates(): void
    {
        // Given
        $key = self::activeKey();

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('Only a staged key can be activated; this one is active.');

        // When
        $key->activate(Fixtures::now());
    }

    /**
     * The retirement window: active, then retiring, still published, due at the date given.
     */
    #[Test]
    public function aRetiringKeyIsNoLongerActiveButStillPublished(): void
    {
        // Given
        $key = self::activeKey();
        $retiringAt = Fixtures::now()->modify('+1 day');
        $dueAt = $retiringAt->modify('+10 minutes');

        // When
        $key->startRetiring($retiringAt, $dueAt);

        // Then
        static::assertSame(KeyStatus::Retiring, $key->status);
        static::assertFalse($key->isActive());
        static::assertTrue($key->isPublished());
        static::assertSame($retiringAt, $key->retiringAt);
        static::assertSame($dueAt, $key->retirementDueAt);
    }

    #[Test]
    public function aRetirementIsNotDueBeforeItsDate(): void
    {
        // Given
        $key = self::activeKey();
        $key->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));

        // When / Then
        static::assertFalse($key->isDue(Fixtures::now()->modify('+9 minutes 59 seconds')));
    }

    #[Test]
    public function aRetirementIsDueFromItsDate(): void
    {
        // Given
        $key = self::activeKey();
        $key->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));

        // When / Then
        static::assertTrue($key->isDue(Fixtures::now()->modify('+10 minutes')));
    }

    #[Test]
    public function aKeyThatIsNotRetiringIsNeverDue(): void
    {
        // Given
        $key = self::activeKey();

        // When / Then
        static::assertFalse($key->isDue(Fixtures::now()->modify('+1 year')));
    }

    #[Test]
    public function aRetirementCannotBeDueBeforeItStarts(): void
    {
        // Given
        $key = self::activeKey();

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $key->startRetiring(Fixtures::now(), Fixtures::now()->modify('-1 second'));
    }

    /**
     * The retirement window: retiring, then retired, gone from the JWK Set.
     */
    #[Test]
    public function aRetiredKeyIsNoLongerPublished(): void
    {
        // Given
        $key = self::activeKey();
        $key->startRetiring(Fixtures::now()->modify('+1 day'), Fixtures::now()->modify('+2 days'));
        $retiredAt = Fixtures::now()->modify('+2 days');

        // When
        $key->retire($retiredAt);

        // Then
        static::assertSame(KeyStatus::Retired, $key->status);
        static::assertFalse($key->isPublished());
        static::assertFalse($key->isDue($retiredAt));
        static::assertSame($retiredAt, $key->retiredAt);
    }

    #[Test]
    #[DataProvider('provideKeysThatCannotStartRetiring')]
    public function onlyAnActiveKeyStartsRetiring(SigningKey $key): void
    {
        // Then
        $this->expectException(LogicException::class);

        // When
        $key->startRetiring(Fixtures::now(), Fixtures::now());
    }

    /**
     * @return iterable<string, array{SigningKey}>
     */
    public static function provideKeysThatCannotStartRetiring(): iterable
    {
        yield 'staged' => [self::key()];
        $retiring = self::activeKey();
        $retiring->startRetiring(Fixtures::now(), Fixtures::now());
        yield 'retiring' => [$retiring];
        yield 'retired' => [self::retiredKey()];
    }

    #[Test]
    #[DataProvider('provideKeysThatCannotRetire')]
    public function onlyARetiringKeyRetires(SigningKey $key): void
    {
        // Then
        $this->expectException(LogicException::class);

        // When
        $key->retire(Fixtures::now());
    }

    /**
     * @return iterable<string, array{SigningKey}>
     */
    public static function provideKeysThatCannotRetire(): iterable
    {
        yield 'staged' => [self::key()];
        yield 'active' => [self::activeKey()];
        yield 'retired' => [self::retiredKey()];
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
     * RFC 7517 §5: the JWK Set lists the published keys only, a staged one included.
     */
    #[Test]
    public function thePublicKeySetServesPublishedKeysOnly(): void
    {
        // Given
        $staged = self::key();
        $retired = self::retiredKey();

        // When
        $set = new PublicKeySet([$staged, $retired]);

        // Then
        static::assertFalse($set->isEmpty());
        static::assertSame([$staged], $set->keys);
        static::assertSame([
            'keys' => [$staged->publicJwk],
        ], $set->toJwks());
    }

    #[Test]
    public function thePublicKeySetFindsAPublishedKeyByKid(): void
    {
        // Given
        $active = self::activeKey();
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

    private static function activeKey(): SigningKey
    {
        $key = self::key();
        $key->activate(Fixtures::now());

        return $key;
    }

    private static function retiredKey(): SigningKey
    {
        $key = self::key(Keys::otherPair()->kid, Keys::otherPair()->publicJwk);
        $key->activate(Fixtures::now());
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());

        return $key;
    }
}
