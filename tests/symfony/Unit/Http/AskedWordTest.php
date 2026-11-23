<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\AskedWord;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Architecture §5.2
 */
final class AskedWordTest extends TestCase
{
    #[Test]
    public function aWordTheTableOffersIsTheOneRead(): void
    {
        // When / Then
        static::assertSame('revoked', self::asked(['state' => 'revoked'])->among('state', ['revoked', 'all']));
    }

    /**
     * @param array<string, mixed> $query
     */
    #[Test]
    #[DataProvider('provideWordsThatNarrowNothing')]
    public function aWordTheTableDoesNotOfferIsReadAsNone(array $query): void
    {
        // When / Then
        static::assertNull(self::asked($query)->among('state', ['revoked', 'all']));
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideWordsThatNarrowNothing(): iterable
    {
        yield 'no word' => [[]];
        yield 'an empty word' => [['state' => '']];
        yield 'a word not offered' => [['state' => 'lost']];
        yield 'a word in another case' => [['state' => 'Revoked']];
        yield 'a list of words' => [['state' => ['revoked']]];
    }

    #[Test]
    #[DataProvider('provideEitherWords')]
    public function oneOfTwoWordsIsReadAsYesOrNo(string $asked, ?bool $read): void
    {
        // When / Then
        static::assertSame($read, self::asked(['by' => $asked])->either('by', 'administrator', 'you'));
    }

    /**
     * @return iterable<string, array{string, bool|null}>
     */
    public static function provideEitherWords(): iterable
    {
        yield 'the first word' => ['administrator', true];
        yield 'the second word' => ['you', false];
        yield 'another word' => ['anyone', null];
    }

    #[Test]
    #[DataProvider('provideTexts')]
    public function whatWasTypedIsReadWithoutTheSpacesAroundIt(mixed $typed, ?string $read): void
    {
        // When / Then
        static::assertSame($read, self::asked(['application' => $typed])->text('application'));
    }

    /**
     * @return iterable<string, array{mixed, string|null}>
     */
    public static function provideTexts(): iterable
    {
        yield 'a few words' => ['  Proton Pass ', 'Proton Pass'];
        yield 'spaces alone' => ['   ', null];
        yield 'a list' => [['Proton'], null];
    }

    #[Test]
    public function anIdentifierIsReadInTheShapeOfRfc9562(): void
    {
        // When
        $read = self::asked(['authenticator' => 'CB69481E-8FF7-4039-93EC-0A2729A154A8'])->uuid('authenticator');

        // Then
        static::assertSame('cb69481e-8ff7-4039-93ec-0a2729a154a8', $read?->toRfc4122());
    }

    #[Test]
    public function aWordThatIsNoIdentifierIsReadAsNone(): void
    {
        // When / Then
        static::assertNull(self::asked(['authenticator' => 'yubikey'])->uuid('authenticator'));
    }

    /**
     * @param array<string, mixed> $query
     */
    private static function asked(array $query): AskedWord
    {
        $requests = new RequestStack([new Request($query)]);

        return new AskedWord($requests);
    }
}
