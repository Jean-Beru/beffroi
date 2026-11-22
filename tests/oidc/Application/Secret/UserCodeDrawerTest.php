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
 * RFC 8628 §5.1, §6.1
 */
final class UserCodeDrawerTest extends TestCase
{
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
     * RFC 8628 §5.1
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
     * @param list<int> $values
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
