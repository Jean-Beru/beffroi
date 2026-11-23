<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Journal;

use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Uid\Uuid;

final class JournalEntryTest extends TestCase
{
    /**
     * Decision 0062
     */
    #[Test]
    #[DataProvider('provideWordsNoRefusalSays')]
    public function aRefusalSaysWhyInAWordOfTheVocabularyOfThisProvider(?string $reason, ?string $method): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The reason of a refusal and the method it refused are words of 64 characters at most, never empty.');

        // When
        new JournalEntry(
            Uuid::v7(),
            Fixtures::tenant(),
            'client_authentication.failed',
            Fixtures::now(),
            Fixtures::context(),
            null,
            null,
            null,
            $reason,
            $method,
        );
    }

    /**
     * @return iterable<string, array{string|null, string|null}>
     */
    public static function provideWordsNoRefusalSays(): iterable
    {
        yield 'an empty reason' => ['', null];
        yield 'a reason longer than 64 characters' => [str_repeat('a', 65), null];
        yield 'an empty method' => ['invalid_secret', ''];
        yield 'a method longer than 64 characters' => ['invalid_secret', str_repeat('m', 65)];
    }
}
