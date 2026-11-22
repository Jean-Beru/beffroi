<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use App\Command\UserEnrolmentTicketCommand;
use Beffroi\Core\Domain\Event\EnrolmentTicketIssued;
use Beffroi\Core\Port\UserRepositoryInterface;
use function preg_match;
use function sprintf;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0025
 */
final class EnrolmentTicketTest extends ConsoleTestCase
{
    #[Test]
    public function theLinkItPrintsOpensThePageOfThatEnrolment(): void
    {
        // Given
        self::user('alice');

        // When
        $tester = self::console(UserEnrolmentTicketCommand::NAME, [
            'username' => 'alice',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertCount(1, self::events(EnrolmentTicketIssued::class));
        $this->browser->request('GET', self::linkOf($tester));
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aSecondLinkTakesTheFirstAway(): void
    {
        // Given
        self::user('alice');
        $first = self::linkOf(self::console(UserEnrolmentTicketCommand::NAME, [
            'username' => 'alice',
        ]));

        // When
        self::console(UserEnrolmentTicketCommand::NAME, [
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
        $tester = self::console(UserEnrolmentTicketCommand::NAME, [
            'username' => 'alice',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('The account of "alice" is disabled; a ticket would open nothing.', self::flattened($tester));
        static::assertSame([], self::events(EnrolmentTicketIssued::class));
    }

    #[Test]
    public function aPersonOfNoSuchNameGetsNoLink(): void
    {
        // When
        $tester = self::console(UserEnrolmentTicketCommand::NAME, [
            'username' => 'nobody',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertSame([], self::events(EnrolmentTicketIssued::class));
    }

    private static function linkOf(CommandTester $tester): string
    {
        static::assertSame(
            1,
            preg_match('#(/enrol/[^\s]+)#', $tester->getDisplay(true), $matches),
            sprintf('No link is printed in: %s', $tester->getDisplay(true)),
        );

        return $matches[1];
    }
}
