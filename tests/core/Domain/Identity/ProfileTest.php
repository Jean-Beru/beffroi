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
    public function itAcceptsTheBirthdateFormsOfOidcCore(): void
    {
        static::assertSame('1990-05-21', (new Profile(birthdate: '1990-05-21'))->birthdate);
        static::assertSame('1990', (new Profile(birthdate: '1990'))->birthdate);
        static::assertSame('0000', (new Profile(birthdate: '0000'))->birthdate);
        static::assertNull(Profile::empty()->birthdate);
    }

    #[Test]
    #[DataProvider('provideInvalidBirthdates')]
    public function itRejectsAnotherBirthdateFormat(string $birthdate): void
    {
        $this->expectException(InvalidArgumentException::class);

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
