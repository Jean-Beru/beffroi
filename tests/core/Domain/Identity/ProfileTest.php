<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Identity;

use Heidi\Core\Domain\Identity\Profile;
use Heidi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ProfileTest extends TestCase
{
    /**
     * OIDC Core §5.1: birthdate is "YYYY-MM-DD", or "YYYY" when only the year is known, "0000" when it is not.
     */
    #[Test]
    #[DataProvider('provideValidBirthdates')]
    public function itAcceptsTheBirthdateFormsOfOidcCore(string $birthdate): void
    {
        // When / Then
        static::assertSame($birthdate, new Profile(birthdate: $birthdate)->birthdate);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValidBirthdates(): iterable
    {
        yield 'full date' => ['1990-05-21'];
        yield 'year only' => ['1990'];
        yield 'unknown year' => ['0000'];
    }

    #[Test]
    public function anEmptyProfileHasNoBirthdate(): void
    {
        // When / Then
        static::assertNull(Profile::empty()->birthdate);
    }

    #[Test]
    #[DataProvider('provideInvalidBirthdates')]
    public function itRejectsAnotherBirthdateFormat(string $birthdate): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new Profile(birthdate: $birthdate);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidBirthdates(): iterable
    {
        yield 'day first' => ['21/05/1990'];
        yield 'trailing characters' => ['1990-05-21T00:00'];
        yield 'leading characters' => ['born 1990'];
    }
}
