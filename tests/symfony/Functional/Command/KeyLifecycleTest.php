<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Command;

use function array_map;
use DateTimeImmutable;
use DateTimeInterface;
use Heidi\Bundle\Message\AdvanceKeyLifecycle;
use Heidi\Bundle\Tests\Functional\MessageHandler\RecordingEventHandler;
use Heidi\Core\Domain\Event\SigningKeyRetired;
use Heidi\Core\Domain\Event\SigningKeyRotated;
use Heidi\Core\Domain\Event\SigningKeyStaged;
use Heidi\Core\Domain\Key\KeyStatus;
use Heidi\Core\Domain\Key\RetirementReason;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Port\KeyPairGeneratorInterface;
use Heidi\Core\Port\KeySealerInterface;
use Heidi\Core\Port\SigningKeyRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function preg_quote;
use function sprintf;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * The operator's side of a rotation without an outage (architecture §3.3, §5.5): one command starts it,
 * time does the rest, through the recurring message of the bundle; every step can be done by hand.
 * The staging delay of this kernel derives from its JWK Set max-age of two minutes: three minutes.
 */
final class KeyLifecycleTest extends ConsoleTestCase
{
    private const string STAGING_DELAY = '+3 minutes';

    /**
     * The first key of a tenant is activated at once: nobody caches an empty JWK Set.
     */
    #[Test]
    public function theFirstKeyOfATenantIsActiveAtOnce(): void
    {
        // When
        $tester = self::console('heidi:keys:rotate');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('active', self::displayed($tester, 'Status'));
        static::assertStringContainsString('nothing to wait for', self::flattened($tester));
        static::assertSame(KeyStatus::Active, self::key(self::displayed($tester, 'Key identifier'))->status);
    }

    /**
     * The acceptance criterion: rotate, then the list shows a staged key next to the active one.
     */
    #[Test]
    public function aRotationStagesAKeyNextToTheActiveOne(): void
    {
        // Given
        $active = self::displayed(self::console('heidi:keys:rotate'), 'Key identifier');

        // When
        $tester = self::console('heidi:keys:rotate');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $staged = self::displayed($tester, 'Key identifier');
        static::assertSame('staged', self::displayed($tester, 'Status'));
        $list = self::flattened(self::console('heidi:keys:list'));
        static::assertMatchesRegularExpression(sprintf('/Key identifier\s+%s\s+Algorithm\s+RS256\s+Status\s+active\s+/', $active), $list);
        static::assertMatchesRegularExpression(sprintf('/Key identifier\s+%s\s+Algorithm\s+RS256\s+Status\s+staged\s+/', $staged), $list);
        static::assertSame(KeyStatus::Active, self::key($active)->status);
    }

    /**
     * The staged key says when it activates: its creation plus the staging delay, derived from the JWK Set
     * max-age of this kernel plus the refetch cooldown of oidc_login.
     */
    #[Test]
    public function theStagedKeySaysWhenItActivates(): void
    {
        // Given
        self::console('heidi:keys:rotate');
        $staged = self::key(self::displayed(self::console('heidi:keys:rotate'), 'Key identifier'));

        // When
        $tester = self::console('heidi:keys:list');

        // Then
        static::assertEquals($staged->createdAt->modify(self::STAGING_DELAY), $staged->activationDueAt);
        static::assertMatchesRegularExpression(sprintf('/Key identifier\s+%s\s+.*?Activates at\s+%s/', $staged->kid, preg_quote($staged->activationDueAt->format(DateTimeInterface::RFC3339), '/')), self::flattened($tester));
    }

    #[Test]
    public function aRotationTellsTheOperatorWhenTheStagedKeySigns(): void
    {
        // Given
        self::console('heidi:keys:rotate');

        // When
        $tester = self::console('heidi:keys:rotate');

        // Then
        $staged = self::key(self::displayed($tester, 'Key identifier'));
        static::assertStringContainsString(sprintf('the scheduled step activates the new key at %s', $staged->activationDueAt->format(DateTimeInterface::RFC3339)), self::flattened($tester));
        static::assertStringContainsString(sprintf('"heidi:keys:activate %s" does it earlier', $staged->kid), self::flattened($tester));
    }

    #[Test]
    public function aRotationNowActivatesAtOnceAndStartsRetiringThePreviousKey(): void
    {
        // Given
        $previous = self::displayed(self::console('heidi:keys:rotate'), 'Key identifier');

        // When
        $tester = self::console('heidi:keys:rotate', [
            '--now' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('active', self::displayed($tester, 'Status'));
        static::assertStringContainsString(sprintf('The key "%s" was active and is now retiring', $previous), self::flattened($tester));
        static::assertSame(KeyStatus::Retiring, self::key($previous)->status);
        static::assertStringContainsString(sprintf('until %s', self::key($previous)->retirementDueAt?->format(DateTimeInterface::RFC3339)), self::flattened($tester));
    }

    /**
     * The compromise path: the previous key leaves the JWK Set at once, the trail says why.
     */
    #[Test]
    public function aRotationForACompromiseRetiresThePreviousKeyAtOnce(): void
    {
        // Given
        $compromised = self::displayed(self::console('heidi:keys:rotate'), 'Key identifier');

        // When
        $tester = self::console('heidi:keys:rotate', [
            '--compromised' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('active', self::displayed($tester, 'Status'));
        static::assertStringContainsString(sprintf('The key "%s" was active and is retired at once', $compromised), self::flattened($tester));
        static::assertSame(KeyStatus::Retired, self::key($compromised)->status);
        static::assertSame([self::displayed($tester, 'Key identifier')], self::publishedKids());
        [$retired] = self::events(SigningKeyRetired::class);
        static::assertSame(RetirementReason::Compromised, $retired->reason);
    }

    #[Test]
    public function activatingAStagedKeyByHandEndsItsStagingWindow(): void
    {
        // Given
        $previous = self::displayed(self::console('heidi:keys:rotate'), 'Key identifier');
        $staged = self::displayed(self::console('heidi:keys:rotate'), 'Key identifier');

        // When
        $tester = self::console('heidi:keys:activate', [
            'kid' => $staged,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('active', self::displayed($tester, 'Status'));
        static::assertStringContainsString(sprintf('The key "%s" was active and is now retiring', $previous), self::flattened($tester));
        static::assertSame(KeyStatus::Active, self::key($staged)->status);
        static::assertSame(KeyStatus::Retiring, self::key($previous)->status);
        static::assertStringContainsString(sprintf('until %s', self::key($previous)->retirementDueAt?->format(DateTimeInterface::RFC3339)), self::flattened($tester));
    }

    /**
     * @param array<string, string|bool> $input
     */
    #[Test]
    #[DataProvider('provideActivationsRefused')]
    public function whatIsNotAStagedKeyIsNotActivated(array $input, string $message): void
    {
        // Given
        $active = self::displayed(self::console('heidi:keys:rotate'), 'Key identifier');

        // When
        $tester = self::console('heidi:keys:activate', array_map(static fn (string|bool $value): string|bool => $value === '{active}' ? $active : $value, $input));

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString($message, self::flattened($tester));
        static::assertSame(KeyStatus::Active, self::key($active)->status);
    }

    /**
     * @return iterable<string, array{array<string, string|bool>, string}>
     */
    public static function provideActivationsRefused(): iterable
    {
        yield 'unknown key' => [[
            'kid' => 'nope',
        ], 'has no key "nope"'];
        yield 'the active key' => [[
            'kid' => '{active}',
        ], 'Only a staged key can be activated; this one is active.'];
    }

    /**
     * The acceptance criterion: a key inside its retirement window is refused without --force.
     */
    #[Test]
    public function retiringAKeyInsideItsWindowIsRefusedWithoutForce(): void
    {
        // Given
        $retiring = self::retiringKey();

        // When
        $tester = self::console('heidi:keys:retire', [
            'kid' => $retiring,
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('is not due for retirement before', self::flattened($tester));
        static::assertStringContainsString('--force', self::flattened($tester));
        static::assertSame(KeyStatus::Retiring, self::key($retiring)->status);
    }

    #[Test]
    public function forcingRetiresAKeyInsideItsWindowAndSaysSo(): void
    {
        // Given
        $retiring = self::retiringKey();

        // When
        $tester = self::console('heidi:keys:retire', [
            'kid' => $retiring,
            '--force' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('retired', self::displayed($tester, 'Status'));
        static::assertStringContainsString('before its retirement date', self::flattened($tester));
        static::assertSame(KeyStatus::Retired, self::key($retiring)->status);
        static::assertSame(RetirementReason::Forced, self::events(SigningKeyRetired::class)[0]->reason);
    }

    /**
     * @param array<string, string|bool> $input
     */
    #[Test]
    #[DataProvider('provideRetirementsRefused')]
    public function whatIsNotARetiringKeyIsNotRetired(array $input, int $status, string $message): void
    {
        // Given
        $active = self::displayed(self::console('heidi:keys:rotate'), 'Key identifier');

        // When
        $tester = self::console('heidi:keys:retire', array_map(static fn (string|bool $value): string|bool => $value === '{active}' ? $active : $value, $input));

        // Then
        static::assertSame($status, $tester->getStatusCode());
        static::assertStringContainsString($message, self::flattened($tester));
        static::assertSame(KeyStatus::Active, self::key($active)->status);
    }

    /**
     * @return iterable<string, array{array<string, string|bool>, int, string}>
     */
    public static function provideRetirementsRefused(): iterable
    {
        yield 'unknown key' => [[
            'kid' => 'nope',
            '--force' => true,
        ], Command::FAILURE, 'has no key "nope"'];
        yield 'the active key' => [[
            'kid' => '{active}',
            '--force' => true,
        ], Command::FAILURE, 'The active key cannot be retired; rotate first.'];
        yield 'a key and --due' => [[
            'kid' => '{active}',
            '--due' => true,
        ], Command::INVALID, 'not both, not neither'];
        yield 'neither a key nor --due' => [[], Command::INVALID, 'not both, not neither'];
    }

    /**
     * The acceptance criterion: --due retires a key past its date and leaves one inside its window.
     */
    #[Test]
    public function retiringTheDueKeysLeavesTheOneInsideItsWindow(): void
    {
        // Given
        $due = self::keyPastItsRetirementDate();
        $insideItsWindow = self::retiringKey();

        // When
        $tester = self::console('heidi:keys:retire', [
            '--due' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString($due->kid, $tester->getDisplay());
        static::assertStringContainsString('1 key(s) of "default" left the JWK Set', self::flattened($tester));
        static::assertSame(KeyStatus::Retired, self::key($due->kid)->status);
        static::assertSame(KeyStatus::Retiring, self::key($insideItsWindow)->status);
    }

    #[Test]
    public function retiringTheDueKeysSaysWhenThereIsNone(): void
    {
        // Given
        self::retiringKey();

        // When
        $tester = self::console('heidi:keys:retire', [
            '--due' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('No key of "default" is past its retirement date.', self::flattened($tester));
    }

    /**
     * The list on request shows the retired keys too, with every date of their life.
     */
    #[Test]
    public function theListShowsARetiredKeyOnRequestOnly(): void
    {
        // Given
        $retired = self::keyPastItsRetirementDate();
        self::console('heidi:keys:retire', [
            '--due' => true,
        ]);

        // When
        $published = self::flattened(self::console('heidi:keys:list'));
        $all = self::flattened(self::console('heidi:keys:list', [
            '--all' => true,
        ]));

        // Then
        static::assertStringNotContainsString($retired->kid, $published);
        static::assertMatchesRegularExpression(sprintf('/Key identifier\s+%s\s+Algorithm\s+RS256\s+Status\s+retired\s+Created at\s+\S+\s+Activated at\s+\S+\s+Retiring since\s+\S+\s+Retirement due at\s+\S+\s+Retired at\s+2026-\S+/', $retired->kid), $all);
    }

    /**
     * The acceptance criterion: the scheduled message activates the staged key once the delay elapsed.
     */
    #[Test]
    public function theScheduledStepActivatesAStagedKeyWhoseDelayElapsed(): void
    {
        // Given
        $previous = self::displayed(self::console('heidi:keys:rotate'), 'Key identifier');
        $due = self::stagedKeyDated(self::currentSecond()->modify('-4 minutes'), self::currentSecond()->modify('-1 minute'));

        // When
        self::tick();

        // Then
        static::assertSame(KeyStatus::Active, self::key($due->kid)->status);
        static::assertSame(KeyStatus::Retiring, self::key($previous)->status);
    }

    /**
     * The acceptance criterion: and not before.
     */
    #[Test]
    public function theScheduledStepLeavesAStagedKeyInsideItsWindow(): void
    {
        // Given
        $active = self::displayed(self::console('heidi:keys:rotate'), 'Key identifier');
        $staged = self::displayed(self::console('heidi:keys:rotate'), 'Key identifier');

        // When
        self::tick();

        // Then
        static::assertSame(KeyStatus::Staged, self::key($staged)->status);
        static::assertSame(KeyStatus::Active, self::key($active)->status);
    }

    #[Test]
    public function theScheduledStepRetiresTheDueKeys(): void
    {
        // Given
        $due = self::keyPastItsRetirementDate();
        $insideItsWindow = self::retiringKey();

        // When
        self::tick();

        // Then
        static::assertSame(KeyStatus::Retired, self::key($due->kid)->status);
        static::assertSame(KeyStatus::Retiring, self::key($insideItsWindow)->status);
    }

    /**
     * The trail says the scheduler did it, and from which schedule.
     */
    #[Test]
    public function theScheduledStepNamesItselfInTheEvents(): void
    {
        // Given
        self::console('heidi:keys:rotate');
        self::stagedKeyDated(self::currentSecond()->modify('-4 minutes'), self::currentSecond()->modify('-1 minute'));

        // When
        self::tick();

        // Then
        [, $rotated] = self::events(SigningKeyRotated::class);
        static::assertNull($rotated->context->ipAddress);
        static::assertStringStartsWith('heidi-scheduler/heidi (', $rotated->context->userAgent ?? '');
    }

    /**
     * Before the first provisioning there is no key to move: the tick does nothing, and fails nothing.
     */
    #[Test]
    public function theScheduledStepDoesNothingWithoutATenant(): void
    {
        // Given
        self::entityManager()
            ->getConnection()
            ->executeStatement('DELETE FROM heidi_tenant');
        self::reload();

        // When
        self::tick();

        // Then
        static::assertSame([], self::events(SigningKeyRotated::class));
    }

    /**
     * Architecture §5.6: the message recurs every minute on the schedule of the bundle, whose transport the
     * worker consumes next to the buses.
     */
    #[Test]
    public function theScheduleOfTheBundleCarriesTheStepEveryMinute(): void
    {
        // When
        $tester = self::console('debug:scheduler');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('heidi', $tester->getDisplay());
        static::assertStringContainsString('every 1 minute', $tester->getDisplay());
        static::assertStringContainsString(AdvanceKeyLifecycle::class, $tester->getDisplay());
    }

    /**
     * The trail says who typed the command: the console names it and the user of the shell.
     */
    #[Test]
    public function theConsoleNamesItselfAndTheOperatorInTheEvents(): void
    {
        // When
        self::console('heidi:keys:rotate');

        // Then
        [$staged] = self::events(SigningKeyStaged::class);
        static::assertNull($staged->context->ipAddress);
        static::assertMatchesRegularExpression('/^heidi-console\/heidi:keys:rotate \([^@]+@.+\)$/', $staged->context->userAgent ?? '');
    }

    /**
     * What the worker does on a tick: the recurring message, handled on the command bus.
     */
    private static function tick(): void
    {
        self::service('test.heidi.command_bus', MessageBusInterface::class)
            ->dispatch(new AdvanceKeyLifecycle());
    }

    /**
     * A key that signed and stopped a moment ago, inside its retirement window of ten minutes.
     */
    private static function retiringKey(): string
    {
        $kid = self::displayed(self::console('heidi:keys:rotate'), 'Key identifier');
        self::console('heidi:keys:rotate', [
            '--now' => true,
        ]);

        return $kid;
    }

    /**
     * A key written as the files would hold it a day after its rotation: retiring since yesterday, due
     * yesterday too, what no command of this kernel can write in the present.
     */
    private static function keyPastItsRetirementDate(): SigningKey
    {
        $yesterday = self::currentSecond()->modify('-1 day');
        $key = self::stagedKeyDated($yesterday->modify('-1 hour'), $yesterday->modify('-1 hour'));
        $key->activate($yesterday->modify('-1 hour'));
        $key->startRetiring($yesterday, $yesterday->modify('+10 minutes'));
        self::keys()
            ->save($key);

        return $key;
    }

    /**
     * A staged key with the dates given, sealed by the KMS of this kernel and saved: how the files look
     * once the staging delay elapsed, without waiting for it.
     */
    private static function stagedKeyDated(DateTimeImmutable $createdAt, DateTimeImmutable $activationDueAt): SigningKey
    {
        $pair = self::service('test.heidi.key_pair_generator', KeyPairGeneratorInterface::class)->generate(SignatureAlgorithm::RS256);
        $sealed = self::service('test.heidi.key_sealer', KeySealerInterface::class)->seal(self::tenant(), $pair->privateJwk);
        $key = new SigningKey($pair->kid, self::tenant(), SignatureAlgorithm::RS256, $pair->publicJwk, $sealed, $createdAt, $activationDueAt);
        self::keys()
            ->save($key);

        return $key;
    }

    private static function key(string $kid): SigningKey
    {
        return self::keys()
            ->find(self::tenant(), $kid) ?? static::fail(sprintf('The key "%s" is not stored.', $kid));
    }

    /**
     * @return list<string>
     */
    private static function publishedKids(): array
    {
        return array_map(static fn (SigningKey $key): string => $key->kid, self::keys()->findPublished(self::tenant()));
    }

    private static function keys(): SigningKeyRepositoryInterface
    {
        return self::service('test.heidi.keys', SigningKeyRepositoryInterface::class);
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return list<T>
     */
    private static function events(string $class): array
    {
        $events = [];
        foreach (self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events as $event) {
            if ($event instanceof $class) {
                $events[] = $event;
            }
        }

        return $events;
    }
}
