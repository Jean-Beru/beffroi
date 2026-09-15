<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Identity;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;

final class SubjectTest extends TestCase
{
    /**
     * OIDC Core §2: "sub" MUST NOT exceed 255 ASCII characters and is case sensitive.
     */
    #[Test]
    public function itKeepsTheValueAsGivenAndComparesCaseSensitively(): void
    {
        $subject = new Subject('248289761001');

        static::assertSame('248289761001', (string) $subject);
        static::assertTrue($subject->equals(new Subject('248289761001')));
        static::assertFalse(new Subject('Alice')->equals(new Subject('alice')));
        static::assertSame(255, strlen((string) new Subject(str_repeat('x', 255))));
    }

    #[Test]
    #[DataProvider('provideInvalidSubjects')]
    public function itRejectsWhatOidcCoreSection2Forbids(string $value): void
    {
        $this->expectException(InvalidArgumentException::class);

        new Subject($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidSubjects(): iterable
    {
        yield 'empty' => [''];
        yield 'longer than 255' => [str_repeat('x', 256)];
        yield 'space' => ['alice smith'];
        yield 'non ASCII' => ['alicé'];
    }
}
