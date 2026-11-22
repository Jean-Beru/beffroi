<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Secret;

use Beffroi\Core\Bridge\Random\FixedRandomness;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * Architecture §4.6
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

    #[Test]
    public function itWritesTheBytesItWasGiven(): void
    {
        // Given
        $drawer = new SecretDrawer(new FixedRandomness([str_repeat("\x00", DrawnSecret::LENGTH)]));

        // When / Then
        static::assertSame(str_repeat('A', 43), $drawer->draw());
    }
}
