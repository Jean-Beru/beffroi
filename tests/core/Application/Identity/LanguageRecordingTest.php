<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use Beffroi\Core\Application\Identity\LanguageRecording;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Issue #471: the language a person told this provider they read, written on their account. It is the one
 * claim this provider needs in order to write to them at all (UserLocale, architecture §5.7).
 */
final class LanguageRecordingTest extends TestCase
{
    #[Test]
    public function theLanguageIsWrittenOnTheAccount(): void
    {
        // Given
        $users = new InMemoryUserRepository();
        $user = self::user($users);

        // When
        new LanguageRecording($users, new MockClock(Fixtures::now()))->record($user, 'fr');

        // Then
        static::assertSame('fr', $users->find($user->id)?->profile->locale);
    }

    /**
     * Saying the whole profile is what provisioning does, and it clears what it is not told; a person
     * naming their language says one thing.
     */
    #[Test]
    public function whatThePersonSaidOfThemselvesIsLeftAlone(): void
    {
        // Given
        $users = new InMemoryUserRepository();
        $user = self::user($users);

        // When
        new LanguageRecording($users, new MockClock(Fixtures::now()))->record($user, 'fr');

        // Then
        $stored = $users->find($user->id)?->profile;
        static::assertSame('Alice Lovelace', $stored?->name);
        static::assertSame('Europe/London', $stored->zoneinfo);
    }

    #[Test]
    public function theAccountSaysItWasUpdated(): void
    {
        // Given
        $users = new InMemoryUserRepository();
        $user = self::user($users);
        $later = Fixtures::now()->modify('+1 hour');

        // When
        new LanguageRecording($users, new MockClock($later))->record($user, 'fr');

        // Then
        static::assertEquals($later, $users->find($user->id)?->updatedAt);
    }

    private static function user(InMemoryUserRepository $users): User
    {
        $user = Fixtures::user();
        $user->updateProfile(new Profile(name: 'Alice Lovelace', zoneinfo: 'Europe/London', locale: 'en-GB'), Fixtures::now());
        $users->save($user);

        return $user;
    }
}
