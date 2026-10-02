<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Secret;

use function array_unique;
use function chr;
use function count;
use Beffroi\Core\Bridge\Random\FixedRandomness;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Oidc\Application\Secret\UserCodeDrawer;
use Beffroi\Oidc\Domain\Device\UserCode;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8628 §5.1, §6.1: the code is drawn from the randomness the provider is given, in the alphabet a user
 * can read aloud, and a byte that would make one character likelier than another is dropped rather than
 * folded.
 */
final class UserCodeDrawerTest extends TestCase
{
    /**
     * A test that cares what the code will be says which bytes it is drawn from: each one names the
     * character of its place in the alphabet, the twenty-first byte naming the first character again.
     */
    #[Test]
    public function itSpellsTheBytesItWasGiven(): void
    {
        // Given
        $drawer = new UserCodeDrawer(new FixedRandomness([self::bytes([0, 1, 2, 3, 19, 20, 21, 239])]));

        // When
        $code = $drawer->draw();

        // Then
        static::assertSame('BCDFZBCZ', $code->value);
    }

    /**
     * A byte at or above twelve whole alphabets names nothing and is dropped: folding it would make four of
     * the twenty characters likelier than the rest, which is exactly the entropy RFC 8628 §5.1 is about.
     */
    #[Test]
    public function itDropsAByteThatWouldBiasTheAlphabet(): void
    {
        // Given
        $drawer = new UserCodeDrawer(new FixedRandomness([
            self::bytes([240, 241, 250, 255, 0, 0, 0, 0]),
            self::bytes([1, 1, 1, 1, 2, 2, 2, 2]),
        ]));

        // When
        $code = $drawer->draw();

        // Then
        static::assertSame('BBBBCCCC', $code->value);
    }

    /**
     * Whatever the bytes say, what comes out is a code of the shape this provider draws.
     */
    #[Test]
    public function whatItDrawsIsAlwaysACodeOfThisProvider(): void
    {
        // Given
        $drawer = new UserCodeDrawer(new PlatformRandomness());

        // When
        $codes = [];
        for ($draw = 0; $draw < 64; ++$draw) {
            $codes[] = $drawer->draw()->value;
        }

        // Then
        foreach ($codes as $code) {
            static::assertTrue(UserCode::isWellFormed($code), $code);
        }
        static::assertGreaterThan(1, count(array_unique($codes)), 'two draws are not the same code');
    }

    /**
     * @param list<int> $values each of them a byte
     */
    private static function bytes(array $values): string
    {
        $bytes = '';
        foreach ($values as $value) {
            $bytes .= chr($value & 0xFF);
        }

        return $bytes;
    }
}
