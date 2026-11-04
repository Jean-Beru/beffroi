<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;

final class SubjectTest extends TestCase
{
    #[Test]
    public function itKeepsTheValueAsGiven(): void
    {
        // When
        $subject = new Subject('248289761001');

        // Then
        static::assertSame('248289761001', (string) $subject);
    }

    #[Test]
    public function itEqualsASubjectOfTheSameValue(): void
    {
        // Given
        $subject = new Subject('248289761001');

        // When / Then
        static::assertTrue($subject->equals(new Subject('248289761001')));
    }

    /**
     * OIDC Core §2
     */
    #[Test]
    public function itComparesCaseSensitively(): void
    {
        // Given
        $subject = new Subject('Alice');

        // When / Then
        static::assertFalse($subject->equals(new Subject('alice')));
    }

    /**
     * OIDC Core §2
     */
    #[Test]
    public function itMayBe255CharactersLong(): void
    {
        // When
        $subject = new Subject(str_repeat('x', 255));

        // Then
        static::assertSame(255, strlen((string) $subject));
    }

    #[Test]
    #[DataProvider('provideInvalidSubjects')]
    public function itRejectsWhatOidcCoreSection2Forbids(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
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
        yield 'a line feed behind a subject that would pass' => ["alice\n"];
    }
}
