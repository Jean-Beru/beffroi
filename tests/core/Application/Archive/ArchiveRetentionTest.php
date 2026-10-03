<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Archive;

use Beffroi\Core\Application\Archive\ArchiveRetention;
use Beffroi\Core\Bridge\InMemory\InMemoryPersonalArchiveRepository;
use Beffroi\Core\Domain\Archive\PersonalArchive;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #453: an archive expires, and what forgets it reads no duration. Every row carries the date it
 * goes away on, set when the person asked for it, so there is nothing for a deployment to say about how
 * long the one file where every sealed column stands in clear at once is kept.
 */
final class ArchiveRetentionTest extends TestCase
{
    #[Test]
    public function anArchivePastItsDateIsForgotten(): void
    {
        // Given
        $archives = new InMemoryPersonalArchiveRepository();
        $archive = self::asked($archives);

        // When
        $forgotten = self::enforcing($archives, $archive->expiresAt)->enforce($archive->tenant);

        // Then
        static::assertSame(1, $forgotten);
        static::assertSame(0, $archives->count());
    }

    #[Test]
    public function anArchiveInsideItsDateIsKept(): void
    {
        // Given
        $archives = new InMemoryPersonalArchiveRepository();
        $archive = self::asked($archives);

        // When
        $forgotten = self::enforcing($archives, Fixtures::now())->enforce($archive->tenant);

        // Then
        static::assertSame(0, $forgotten);
        static::assertSame(1, $archives->count());
    }

    /**
     * An archive of another tenant is not this tenant's to forget, as it is not its to read.
     */
    #[Test]
    public function anArchiveOfAnotherTenantIsNotForgotten(): void
    {
        // Given
        $archives = new InMemoryPersonalArchiveRepository();
        $archive = self::asked($archives);

        // When
        $forgotten = self::enforcing($archives, $archive->expiresAt)->enforce(Fixtures::tenant('other', 'https://id.other.example'));

        // Then
        static::assertSame(0, $forgotten);
        static::assertSame(1, $archives->count());
    }

    private static function enforcing(InMemoryPersonalArchiveRepository $archives, DateTimeImmutable $at): ArchiveRetention
    {
        return new ArchiveRetention($archives, new MockClock($at));
    }

    private static function asked(InMemoryPersonalArchiveRepository $archives): PersonalArchive
    {
        $archive = PersonalArchive::asked(Uuid::v7(), Fixtures::user(), Fixtures::now());
        $archives->save($archive);

        return $archive;
    }
}
