<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Configuration;

use Beffroi\Bundle\Configuration\BoundedLifetime;
use Beffroi\Bundle\Configuration\TokensSection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Issue #911: a lifetime the tree bounds is held to the same bounds when the container builds it, which is
 * where a number an environment variable carries is first a number. RFC 6749 §4.1.2 is the bound of a code.
 */
final class BoundedLifetimeTest extends TestCase
{
    #[Test]
    #[DataProvider('provideNumbersWithinTheBounds')]
    public function aNumberWithinTheBoundsIsTheLifetime(int $seconds): void
    {
        // When
        $lifetime = BoundedLifetime::interval($seconds, 'authorization_code_ttl', TokensSection::MAX_AUTHORIZATION_CODE_TTL);

        // Then
        static::assertSame($seconds, $lifetime->s);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideNumbersWithinTheBounds(): iterable
    {
        yield 'a second' => [1];
        yield 'the bound itself' => [TokensSection::MAX_AUTHORIZATION_CODE_TTL];
    }

    #[Test]
    #[DataProvider('provideNumbersOutsideTheBounds')]
    public function aNumberOutsideTheBoundsIsRefusedByTheNodeItWasWrittenUnder(int $seconds): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs(\sprintf(
            'The "beffroi" configuration key "authorization_code_ttl" is a number of seconds from 1 to 600, %d given.',
            $seconds,
        ));

        // When
        BoundedLifetime::interval($seconds, 'authorization_code_ttl', TokensSection::MAX_AUTHORIZATION_CODE_TTL);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideNumbersOutsideTheBounds(): iterable
    {
        yield 'nothing' => [0];
        yield 'a negative number' => [-60];
        yield 'a second past the bound' => [TokensSection::MAX_AUTHORIZATION_CODE_TTL + 1];
    }
}
