<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctor;

use Beffroi\Bundle\Command\DoctorCommand;
use Beffroi\Bundle\Doctor\Finding;
use Beffroi\Bundle\Doctor\NotificationsLanePatience;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * Issue #196: the retirement window of a signing key covers how long a logout token may still be on its
 * way, and that number is true of a deployment only because the lane the notifications are routed to is
 * driven by the policy of the bundle. Nothing else sees it: the bundle cannot refuse an application's
 * transport, and in a test environment every lane is synchronous, so no functional test of an application
 * covers the wiring. A line of YAML re-opens what #155 closed.
 *
 * So it is judged on containers and not on files: this kernel as the bundle wires it, where the contract
 * of Messenger is prepended with the policy on that lane, and the same kernel in an environment that
 * routes the notifications somewhere of its own (config_test_own_notifications_lane.yml).
 *
 * The doctor reads and writes nothing, so neither does this: no schema, no tenant, no row.
 */
final class DoctorTest extends KernelTestCase
{
    /**
     * The environment whose container routes what the provider carries to a third party to a lane of its
     * own, ten retries a minute apart.
     */
    private const string OWN_LANE = 'test_own_notifications_lane';

    protected function tearDown(): void
    {
        self::ensureKernelShutdown();
    }

    #[Test]
    public function theDoctorPassesOnTheLaneTheBundleWires(): void
    {
        // When
        $doctor = self::doctor('test');

        // Then
        static::assertSame(Command::SUCCESS, $doctor->getStatusCode(), $doctor->getDisplay());
    }

    /**
     * A point that passes says the two lengths of time it read, a point that says nothing but "yes" being
     * a point nobody can tell from a point that was never looked at: how long a logout token is retried,
     * and how long one can still be verified.
     */
    #[Test]
    public function thePassingPointSaysHowLongItTriesAndHowLongWhatItSendsLasts(): void
    {
        // Given
        $finding = self::finding('test');

        // When / Then
        static::assertSame(
            [
                true,
                'A logout token is retried on "async_notifications" for 3 minutes 20 seconds and stops being verifiable after 3 minutes 55 seconds, both read from the schedule this provider publishes (Beffroi\Bundle\Messenger\NotificationRetryPolicy): a client that is restarting is reached, and nothing arrives after the "exp" of the token has passed or after the key that signed it has left the JWK Set.',
            ],
            [$finding->green, $finding->lines[0] ?? null],
        );
    }

    #[Test]
    public function theDoctorFailsOnALaneOfTheApplicationsOwn(): void
    {
        // When
        $doctor = self::doctor(self::OWN_LANE);

        // Then
        static::assertSame(Command::FAILURE, $doctor->getStatusCode(), $doctor->getDisplay());
    }

    /**
     * One line, the transport and both lengths of time: ten minutes of retries where what is retried stops
     * being verifiable after not quite four.
     */
    #[Test]
    public function theFailingPointNamesTheTransportAndBothLengthsOfTime(): void
    {
        // Given
        $finding = self::finding(self::OWN_LANE);

        // When / Then
        static::assertSame(
            [
                false,
                'This deployment retries a logout token on the transport "own_notifications" for 10 minutes. One stops being verifiable after 3 minutes 55 seconds, which is how far ahead its "exp" is set and how long the key that signed it stays in the JWK Set, both read from the schedule this provider publishes (Beffroi\Bundle\Messenger\NotificationRetryPolicy); that transport is retried by Symfony\Component\Messenger\Retry\MultiplierRetryStrategy instead.',
            ],
            [$finding->green, $finding->lines[0] ?? null],
        );
    }

    /**
     * What a point that fails owes the reader, because what the doctor finds is by construction what
     * nothing else shows: what it costs, in what somebody would see, then what to do.
     */
    #[Test]
    public function theFailingPointSaysWhatItCostsAndWhatToDo(): void
    {
        // Given
        $finding = self::finding(self::OWN_LANE);

        // When / Then
        static::assertSame(
            [
                'What it costs: a user who signs out stays signed in on a client that was being retried, that client refusing a token whose "exp" has passed or whose signing key its JWK Set no longer publishes after 3 minutes 55 seconds. It shows after a key rotation or after a client restarts, it is never visible in a browser, and no test of a deployment covers it, every lane being synchronous in a test environment.',
                NotificationsLanePatience::WHAT_TO_DO,
            ],
            [$finding->lines[1] ?? null, $finding->lines[2] ?? null],
        );
    }

    /**
     * The command on a kernel booted in the given environment; each environment compiles a container of
     * its own, into the cache directory named after it.
     */
    private static function doctor(string $environment): CommandTester
    {
        $application = new Application(self::reboot($environment));
        $application->setAutoExit(false);
        $tester = new CommandTester($application->find(DoctorCommand::NAME));
        $tester->execute([]);

        return $tester;
    }

    private static function finding(string $environment): Finding
    {
        self::reboot($environment);
        $check = self::getContainer()->get('test.beffroi.notifications_lane');
        static::assertInstanceOf(NotificationsLanePatience::class, $check);

        return $check->finding();
    }

    private static function reboot(string $environment): KernelInterface
    {
        self::ensureKernelShutdown();

        return self::bootKernel([
            'environment' => $environment,
        ]);
    }
}
