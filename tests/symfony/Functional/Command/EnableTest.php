<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use App\Command\UserEnableCommand;
use Beffroi\Core\Domain\Event\PersonEnabled;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use function count;
use function str_contains;
use Symfony\Component\Console\Command\Command;

/**
 * Decision 0038
 */
final class EnableTest extends ConsoleTestCase
{
    #[Test]
    public function aDisabledPersonMaySignInAgain(): void
    {
        // Given
        $alice = self::user('alice');
        $alice->disable(self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($alice);

        // When
        $tester = self::console(UserEnableCommand::NAME, ['username' => 'alice']);

        // Then
        self::reload();
        static::assertSame(
            [Command::SUCCESS, true, 1],
            [
                $tester->getStatusCode(),
                self::service('test.beffroi.users', UserRepositoryInterface::class)->find($alice->id)?->isEnabled(),
                count(self::events(PersonEnabled::class)),
            ],
        );
    }

    #[Test]
    public function aPersonEnabledAlreadyIsLeftAsTheyAre(): void
    {
        // Given
        self::user('alice');

        // When
        $tester = self::console(UserEnableCommand::NAME, ['username' => 'alice']);

        // Then
        static::assertSame(
            [Command::SUCCESS, true, []],
            [$tester->getStatusCode(), str_contains(self::flattened($tester), 'was enabled already'), self::events(PersonEnabled::class)],
        );
    }
}
