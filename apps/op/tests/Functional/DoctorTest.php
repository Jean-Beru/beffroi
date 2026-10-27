<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use Beffroi\Bundle\Command\DoctorCommand;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * Issue #196: what the retirement window of a signing key publishes is true of this deployment only
 * because the lane its notifications are routed to is tried again on the policy the bundle publishes. The
 * lane is the bundle's, on the transport the deployment names (BEFFROI_MESSENGER_DSN, issue #919), and a
 * lane this application declared again, or a route of the marker elsewhere, would be a provider that goes
 * on working and a window that announces a budget nobody follows, which nothing in a browser shows.
 *
 * So the doctor is asked of the container this application boots and not of the file it was written from.
 * It reads and writes nothing, so this needs neither the schema nor a row.
 */
final class DoctorTest extends KernelTestCase
{
    #[Test]
    public function theDoctorPassesOnThisApplicationAsItIsWired(): void
    {
        // Given
        $application = new Application(self::bootKernel());
        $application->setAutoExit(false);
        $doctor = new CommandTester($application->find(DoctorCommand::NAME));

        // When
        $doctor->execute([]);

        // Then
        static::assertSame(Command::SUCCESS, $doctor->getStatusCode(), $doctor->getDisplay());
    }
}
