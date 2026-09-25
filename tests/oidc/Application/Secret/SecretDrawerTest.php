<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Secret;

use Heidi\Core\Bridge\Random\FixedRandomness;
use Heidi\Core\Bridge\Random\PlatformRandomness;
use Heidi\Oidc\Application\Secret\SecretDrawer;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * Architecture §4.6: every value this provider hands out and recognises again is drawn here, 256 bits of
 * the randomness it was given, written in base64url.
 */
final class SecretDrawerTest extends TestCase
{
    #[Test]
    public function itDraws256BitsInBase64url(): void
    {
        // When
        $value = new SecretDrawer(new PlatformRandomness())->draw();

        // Then
        static::assertTrue(DrawnSecret::isValue($value));
    }

    #[Test]
    public function twoDrawsDiffer(): void
    {
        // Given
        $drawer = new SecretDrawer(new PlatformRandomness());

        // When / Then
        static::assertNotSame($drawer->draw(), $drawer->draw());
    }

    /**
     * The value is the randomness it was given and nothing else, which is what lets a test fix it.
     */
    #[Test]
    public function itWritesTheBytesItWasGiven(): void
    {
        // Given
        $drawer = new SecretDrawer(new FixedRandomness([str_repeat("\x00", DrawnSecret::LENGTH)]));

        // When / Then
        static::assertSame(str_repeat('A', 43), $drawer->draw());
    }
}
