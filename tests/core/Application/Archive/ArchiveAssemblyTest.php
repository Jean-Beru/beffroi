<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Archive;

use Beffroi\Core\Application\Archive\ArchiveAssembly;
use Beffroi\Core\Bridge\InMemory\InMemoryPersonalArchiveRepository;
use Beffroi\Core\Domain\Archive\PersonalArchive;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ArchiveChapterInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use function array_keys;
use DateTimeImmutable;
use const JSON_THROW_ON_ERROR;
use function json_decode;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

final class ArchiveAssemblyTest extends TestCase
{
    #[Test]
    public function theArchiveIsBuiltFromTheChaptersThatAreWired(): void
    {
        // Given
        $archives = new InMemoryPersonalArchiveRepository();
        $archive = self::asked($archives);

        // When
        self::assembling($archives, [self::chapter('groups', [['name' => 'engineering']])])->assemble($archive->tenant, $archive->id);

        // Then
        static::assertSame([['name' => 'engineering']], self::read($archive)['groups']);
    }

    #[Test]
    public function theDocumentSaysWhatItIsAndWhoItIsOf(): void
    {
        // Given
        $archives = new InMemoryPersonalArchiveRepository();
        $archive = self::asked($archives);

        // When
        self::assembling($archives)->assemble($archive->tenant, $archive->id);

        // Then
        static::assertSame(
            [
                'id' => $archive->id->toRfc4122(),
                'tenant' => $archive->tenant->slug,
                'person' => $archive->user->subject->value,
                'asked_at' => $archive->askedAt->format('c'),
                'built_at' => Fixtures::now()->format('c'),
                'expires_at' => $archive->expiresAt->format('c'),
            ],
            self::read($archive)[ArchiveAssembly::ABOUT],
        );
    }

    #[Test]
    public function theDocumentHoldsTheChaptersInTheOrderTheyAreWired(): void
    {
        // Given
        $archives = new InMemoryPersonalArchiveRepository();
        $archive = self::asked($archives);

        // When
        self::assembling($archives, [self::chapter('profile', []), self::chapter('journal', [])])->assemble($archive->tenant, $archive->id);

        // Then
        static::assertSame([ArchiveAssembly::ABOUT, 'profile', 'journal'], array_keys(self::read($archive)));
    }

    #[Test]
    public function anArchiveAlreadyBuiltIsLeftAlone(): void
    {
        // Given
        $archives = new InMemoryPersonalArchiveRepository();
        $archive = self::asked($archives);
        $archive->fill('{"was":"here"}', Fixtures::now());

        // When
        self::assembling($archives, [self::chapter('groups', [['name' => 'engineering']])])->assemble($archive->tenant, $archive->id);

        // Then
        static::assertSame('{"was":"here"}', $archive->content);
    }

    #[Test]
    public function anArchiveThatExpiredBeforeItsTurnIsNotBuilt(): void
    {
        // Given
        $archives = new InMemoryPersonalArchiveRepository();
        $archive = self::asked($archives);

        // When
        self::assembling($archives, at: $archive->expiresAt)->assemble($archive->tenant, $archive->id);

        // Then
        static::assertFalse($archive->isReady());
    }

    #[Test]
    public function anArchiveThatIsNotThereIsNotBuilt(): void
    {
        // Given
        $archives = new InMemoryPersonalArchiveRepository();

        // When
        self::assembling($archives)->assemble(Fixtures::tenant(), Uuid::v7());

        // Then
        static::assertSame(0, $archives->count());
    }

    #[Test]
    public function anArchiveOfAnotherTenantIsNotBuilt(): void
    {
        // Given
        $archives = new InMemoryPersonalArchiveRepository();
        $archive = self::asked($archives);

        // When
        self::assembling($archives)->assemble(Fixtures::tenant('other', 'https://id.other.example'), $archive->id);

        // Then
        static::assertFalse($archive->isReady());
    }

    /**
     * @return array<string, mixed>
     */
    private static function read(PersonalArchive $archive): array
    {
        static::assertIsString($archive->content);
        $document = json_decode($archive->content, true, 512, JSON_THROW_ON_ERROR);
        static::assertIsArray($document);

        /** @var array<string, mixed> $document */
        return $document;
    }

    /**
     * @param list<ArchiveChapterInterface> $chapters
     */
    private static function assembling(
        InMemoryPersonalArchiveRepository $archives,
        array $chapters = [],
        ?DateTimeImmutable $at = null,
    ): ArchiveAssembly {
        return new ArchiveAssembly($archives, $chapters, new MockClock($at ?? Fixtures::now()));
    }

    private static function asked(InMemoryPersonalArchiveRepository $archives): PersonalArchive
    {
        $archive = PersonalArchive::asked(Uuid::v7(), Fixtures::user(), Fixtures::now());
        $archives->save($archive);

        return $archive;
    }

    /**
     * @param list<array<string, mixed>> $lines
     */
    private static function chapter(string $name, array $lines): ArchiveChapterInterface
    {
        return new readonly class($name, $lines) implements ArchiveChapterInterface {
            /**
             * @param list<array<string, mixed>> $lines
             */
            public function __construct(
                private string $name,
                private array $lines,
            ) {
            }

            public function name(): string
            {
                return $this->name;
            }

            public function of(User $user): array
            {
                return $this->lines;
            }
        };
    }
}
