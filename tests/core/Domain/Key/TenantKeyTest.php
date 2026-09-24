<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Key;

use function array_map;
use DateTimeImmutable;
use Heidi\Core\Domain\Key\KeyStatus;
use Heidi\Core\Domain\Key\KeyUse;
use Heidi\Core\Domain\Key\PublicKeySet;
use Heidi\Core\Domain\Key\TenantKey;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class TenantKeyTest extends TestCase
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

    /**
     * The staging window is a fact of the key, written when it is created.
     */
    #[Test]
    public function aNewKeySaysWhenItsActivationIsDue(): void
    {
        // When
        $key = new TenantKey(
            Keys::pair()->kid,
            Fixtures::tenant(),
            Algorithms::rs256(),
            Keys::pair()->publicJwk,
            'sealed',
            Fixtures::now(),
            Fixtures::now()->modify('+6 minutes'),
        );

        // Then
        static::assertEquals(Fixtures::now()->modify('+6 minutes'), $key->activationDueAt);
    }

    #[Test]
    public function anActivationCannotBeDueBeforeTheKeyExists(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The activation of a key is due when it is created at the earliest.');

        // When
        new TenantKey(
            Keys::pair()->kid,
            Fixtures::tenant(),
            Algorithms::rs256(),
            Keys::pair()->publicJwk,
            'sealed',
            Fixtures::now(),
            Fixtures::now()->modify('-1 second'),
        );
    }

    #[Test]
    public function anActivationIsNotDueBeforeItsDate(): void
    {
        // Given
        $key = self::stagedKey(Fixtures::now()->modify('+6 minutes'));

        // When / Then
        static::assertFalse($key->isDueForActivation(Fixtures::now()->modify('+5 minutes 59 seconds')));
    }

    #[Test]
    public function anActivationIsDueFromItsDate(): void
    {
        // Given
        $key = self::stagedKey(Fixtures::now()->modify('+6 minutes'));

        // When / Then
        static::assertTrue($key->isDueForActivation(Fixtures::now()->modify('+6 minutes')));
    }

    #[Test]
    public function aKeyThatIsNotStagedIsNeverDueForActivation(): void
    {
        // Given
        $key = self::activeKey();

        // When / Then
        static::assertFalse($key->isDueForActivation(Fixtures::now()->modify('+1 year')));
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
    public function onlyAnActiveKeyStartsRetiring(TenantKey $key): void
    {
        // Then
        $this->expectException(LogicException::class);

        // When
        $key->startRetiring(Fixtures::now(), Fixtures::now());
    }

    /**
     * @return iterable<string, array{TenantKey}>
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
    public function onlyARetiringKeyRetires(TenantKey $key): void
    {
        // Then
        $this->expectException(LogicException::class);

        // When
        $key->retire(Fixtures::now());
    }

    /**
     * @return iterable<string, array{TenantKey}>
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
        new TenantKey($kid, Fixtures::tenant(), Algorithms::rs256(), $publicJwk, 'sealed', Fixtures::now(), Fixtures::now());
    }

    /**
     * @return iterable<string, array{array<string, string>}|array{array<string, string>, string}>
     */
    public static function provideBadPublicJwks(): iterable
    {
        $good = Keys::pair()->publicJwk;
        yield 'kid mismatch' => [$good, 'another-kid'];
        yield 'missing alg' => [
            [
                'kty' => 'RSA',
                'kid' => $good['kid'],
                'use' => 'sig',
                'n' => $good['n'],
                'e' => $good['e'],
            ],
            $good['kid'],
        ];
        yield 'wrong use' => [
            [
                ...$good,
                'use' => 'enc',
            ],
            $good['kid'],
        ];
        yield 'wrong key type' => [
            [
                ...$good,
                'kty' => 'EC',
            ],
            $good['kid'],
        ];
        yield 'private exponent present' => [
            [
                ...$good,
                'd' => 'secret',
            ],
            $good['kid'],
        ];
        yield 'empty kid' => [
            [
                ...$good,
                'kid' => '',
            ],
            '',
        ];
    }

    /**
     * RFC 7517 §4.2: the "use" of the JWK is the use of the algorithm the key was generated for, asserted
     * and not assumed. A key of an encryption algorithm publishes "enc".
     */
    #[Test]
    public function anEncryptionKeyIsPublishedForEncryption(): void
    {
        // When
        $key = self::encryptionKey();

        // Then
        static::assertSame('enc', $key->publicJwk['use']);
        static::assertSame(KeyUse::Encryption, $key->algorithm->keyUse());
    }

    /**
     * The other way round of "wrong use": a JWK that says it signs cannot describe a key generated to be
     * encrypted to.
     */
    #[Test]
    public function aJwkThatSignsDoesNotDescribeAnEncryptionKey(): void
    {
        // Given
        $jwk = [
            ...Keys::encryptionPair()->publicJwk,
            'use' => 'sig',
        ];

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The public JWK must carry "use" = "enc".');

        // When
        new TenantKey(Keys::encryptionPair()->kid, Fixtures::tenant(), Algorithms::ecdhEsA256Kw(), $jwk, 'sealed', Fixtures::now(), Fixtures::now());
    }

    /**
     * RFC 7517 §5 and §4.2: the set carries both uses, and a consumer asks for the one it needs.
     */
    #[Test]
    public function thePublicKeySetCarriesBothUsesAndNarrowsToOne(): void
    {
        // Given
        $signing = self::key();
        $encryption = self::encryptionKey();

        // When
        $set = new PublicKeySet([$signing, $encryption]);

        // Then
        static::assertSame([$signing->kid, $encryption->kid], array_map(static fn (TenantKey $key): string => $key->kid, $set->keys));
        static::assertSame([$signing->kid], array_map(static fn (TenantKey $key): string => $key->kid, $set->forUse(KeyUse::Signature)->keys));
        static::assertSame([$encryption->kid], array_map(static fn (TenantKey $key): string => $key->kid, $set->forUse(KeyUse::Encryption)->keys));
    }

    /**
     * A key of one use is not found among the keys of the other, which is what keeps a signature from
     * being verified against a key published to be encrypted to.
     */
    #[Test]
    public function aKeyIsNotFoundAmongTheKeysOfTheOtherUse(): void
    {
        // Given
        $set = new PublicKeySet([self::key(), self::encryptionKey()]);

        // When / Then
        static::assertNull($set->forUse(KeyUse::Signature)->find(Keys::encryptionPair()->kid));
    }

    #[Test]
    public function itCarriesItsSealedPrivateMaterial(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new TenantKey(Keys::pair()->kid, Fixtures::tenant(), Algorithms::rs256(), Keys::pair()->publicJwk, '', Fixtures::now(), Fixtures::now());
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
        $set = PublicKeySet::published([$staged, $retired]);

        // Then
        static::assertFalse($set->isEmpty());
        static::assertSame([$staged], $set->keys);
        static::assertSame(
            [
                'keys' => [$staged->publicJwk],
            ],
            $set->toJwks(),
        );
    }

    #[Test]
    public function thePublicKeySetFindsAPublishedKeyByKid(): void
    {
        // Given
        $active = self::activeKey();
        $set = PublicKeySet::published([$active, self::retiredKey()]);

        // When / Then
        static::assertSame($active, $set->find($active->kid));
    }

    #[Test]
    public function thePublicKeySetDoesNotFindARetiredKey(): void
    {
        // Given
        $retired = self::retiredKey();
        $set = PublicKeySet::published([self::key(), $retired]);

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

    private static function encryptionKey(): TenantKey
    {
        return new TenantKey(
            Keys::encryptionPair()->kid,
            Fixtures::tenant(),
            Algorithms::ecdhEsA256Kw(),
            Keys::encryptionPair()->publicJwk,
            'sealed',
            Fixtures::now(),
            Fixtures::now(),
        );
    }

    /**
     * @param array<string, string>|null $publicJwk
     */
    private static function key(?string $kid = null, ?array $publicJwk = null): TenantKey
    {
        return new TenantKey(
            $kid ?? Keys::pair()->kid,
            Fixtures::tenant(),
            Algorithms::rs256(),
            $publicJwk ?? Keys::pair()->publicJwk,
            'sealed',
            Fixtures::now(),
            Fixtures::now(),
        );
    }

    private static function stagedKey(DateTimeImmutable $activationDueAt): TenantKey
    {
        return new TenantKey(Keys::pair()->kid, Fixtures::tenant(), Algorithms::rs256(), Keys::pair()->publicJwk, 'sealed', Fixtures::now(), $activationDueAt);
    }

    private static function activeKey(): TenantKey
    {
        $key = self::key();
        $key->activate(Fixtures::now());

        return $key;
    }

    private static function retiredKey(): TenantKey
    {
        $key = self::key(Keys::otherPair()->kid, Keys::otherPair()->publicJwk);
        $key->activate(Fixtures::now());
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());

        return $key;
    }

    /**
     * A set says what it is given: a key that has retired is refused rather than quietly dropped, so
     * that nobody serves a JWK Set shorter than they think.
     */
    #[Test]
    public function aRetiredKeyIsRefusedByTheSetRatherThanDropped(): void
    {
        // Given
        $retired = self::retiredKey();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('has retired and is not published');

        // When
        new PublicKeySet([$retired]);
    }
}
