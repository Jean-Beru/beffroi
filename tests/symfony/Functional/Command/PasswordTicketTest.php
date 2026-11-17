<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use App\Command\UserPasswordTicketCommand;
use Beffroi\Core\Domain\Event\PasswordTicketIssued;
use Beffroi\Core\Domain\Session\PhishingResistant;
use Beffroi\Core\Port\UserRepositoryInterface;
use function preg_match;
use function sprintf;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0026
 */
final class PasswordTicketTest extends ConsoleTestCase
{
    #[Test]
    public function theLinkItPrintsOpensThePageOfThatPassword(): void
    {
        // Given
        self::user('alice');

        // When
        $tester = self::console(UserPasswordTicketCommand::NAME, [
            'username' => 'alice',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertCount(1, self::events(PasswordTicketIssued::class));
        $this->browser->request('GET', self::linkOf($tester));
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aSecondLinkTakesTheFirstAway(): void
    {
        // Given
        self::user('alice');
        $first = self::linkOf(self::console(UserPasswordTicketCommand::NAME, [
            'username' => 'alice',
        ]));

        // When
        self::console(UserPasswordTicketCommand::NAME, [
            'username' => 'alice',
        ]);

        // Then
        $this->browser->request('GET', $first);
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aDisabledPersonGetsNoLink(): void
    {
        // Given
        $alice = self::user('alice');
        $alice->disable(self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($alice);

        // When
        $tester = self::console(UserPasswordTicketCommand::NAME, [
            'username' => 'alice',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('The account of "alice" is disabled; a ticket would open nothing.', self::flattened($tester));
        static::assertSame([], self::events(PasswordTicketIssued::class));
    }

    /**
     * Decision 0025
     */
    #[Test]
    public function aTenantThatSignsInWithoutAPasswordGivesNoLink(): void
    {
        // Given
        self::user('alice');
        self::harden(new PhishingResistant());

        // When
        $tester = self::console(UserPasswordTicketCommand::NAME, [
            'username' => 'alice',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('A ticket that poses a password would open nothing.', self::flattened($tester));
    }

    private static function linkOf(CommandTester $tester): string
    {
        static::assertSame(
            1,
            preg_match('#(/password/[^\s]+)#', $tester->getDisplay(true), $matches),
            sprintf('No link is printed in: %s', $tester->getDisplay(true)),
        );

        return $matches[1];
    }
}
