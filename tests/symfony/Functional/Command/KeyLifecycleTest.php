<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use function array_filter;
use function array_map;
use function array_values;
use DateTimeImmutable;
use DateTimeInterface;
use App\Message\AdvanceKeyLifecycle;
use App\Message\RemoveUnusedClients;
use App\Messenger\MessengerContract;
use App\Tests\Symfony\Fixture\QueuedBodies;
use Beffroi\Core\Bridge\JwtLibrary\SealedMessageBody;
use Beffroi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Beffroi\Core\Domain\Event\TenantKeyRetired;
use Beffroi\Core\Domain\Event\TenantKeyRotated;
use Beffroi\Core\Domain\Event\TenantKeyStaged;
use Beffroi\Core\Domain\Key\KeyStatus;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Key\RetirementReason;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Port\KeyPairGeneratorInterface;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Application\Discovery\JwksHandler;
use Doctrine\DBAL\Connection;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function preg_match;
use function preg_match_all;
use function preg_quote;
use function random_bytes;
use function sprintf;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\KeyManagement\EnvelopeEncrypter;
use Symfony\Component\KeyManagement\KeyLoader\InMemoryKeyLoader;
use Symfony\Component\KeyManagement\Local\SodiumKms;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * Architecture §3.3, §5.5
 */
final class KeyLifecycleTest extends ConsoleTestCase
{
    private const string STAGING_DELAY = '+3 minutes';

    #[Test]
    public function theFirstKeyOfATenantIsActiveAtOnce(): void
    {
        // When
        $tester = self::console('beffroi:keys:rotate');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('active', self::displayed($tester, 'Status'));
        static::assertStringContainsString('nothing to wait for', self::flattened($tester));
        static::assertSame(KeyStatus::Active, self::key(self::displayed($tester, 'Key identifier'))->status);
    }

    /**
     * Architecture §3.3
     */
    #[Test]
    public function anOperatorNamesTheAlgorithmTheKeySignsWith(): void
    {
        // Given
        $rs256 = self::displayed(self::console('beffroi:keys:rotate'), 'Key identifier');

        // When
        $tester = self::console('beffroi:keys:rotate', [
            '--algorithm' => 'ES256',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('ES256', self::displayed($tester, 'Algorithm'));
        static::assertSame('active', self::displayed($tester, 'Status'));
        static::assertSame(KeyStatus::Active, self::key($rs256)->status);
    }

    #[Test]
    public function anOperatorNamesAnAlgorithmTheKeyIsEncryptedToWith(): void
    {
        // Given
        $signing = self::displayed(self::console('beffroi:keys:rotate'), 'Key identifier');

        // When
        $tester = self::console('beffroi:keys:rotate', [
            '--algorithm' => 'ECDH-ES+A256KW',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('enc', self::displayed($tester, 'Use'));
        static::assertSame('active', self::displayed($tester, 'Status'));
        static::assertSame(KeyStatus::Active, self::key($signing)->status);
    }

    /**
     * RFC 7517 §4.2
     */
    #[Test]
    public function theJwkSetPublishesTheEncryptionKeyBesideTheSigningOne(): void
    {
        // Given
        $signing = self::displayed(self::console('beffroi:keys:rotate'), 'Key identifier');
        $encryption = self::displayed(self::console('beffroi:keys:rotate', [
            '--algorithm' => 'ECDH-ES+A256KW',
        ]), 'Key identifier');

        // When
        $published = self::service('test.beffroi.jwks', JwksHandler::class)->handle(self::tenant())->keys;

        // Then
        static::assertSame([$signing, $encryption], array_map(static fn (TenantKey $key): string => $key->kid, $published->keys));
        static::assertSame('sig', $published->find($signing)?->publicJwk['use']);
        static::assertSame('enc', $published->find($encryption)?->publicJwk['use']);
        static::assertSame([$encryption], array_map(static fn (TenantKey $key): string => $key->kid, $published->forUse(KeyUse::Encryption)->keys));
    }

    #[Test]
    public function aStagedEncryptionKeyIsActivatedByTheSameCommand(): void
    {
        // Given
        $first = self::displayed(self::console('beffroi:keys:rotate', [
            '--algorithm' => 'ECDH-ES+A256KW',
        ]), 'Key identifier');
        $staged = self::displayed(self::console('beffroi:keys:rotate', [
            '--algorithm' => 'ECDH-ES+A256KW',
        ]), 'Key identifier');

        // When
        $tester = self::console('beffroi:keys:activate', [
            'kid' => $staged,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame(KeyStatus::Active, self::key($staged)->status);
        static::assertSame(KeyStatus::Retiring, self::key($first)->status);
    }

    #[Test]
    public function aRetiringEncryptionKeyIsRetiredByTheSameCommand(): void
    {
        // Given
        $first = self::displayed(self::console('beffroi:keys:rotate', [
            '--algorithm' => 'ECDH-ES+A256KW',
        ]), 'Key identifier');
        self::console('beffroi:keys:rotate', [
            '--algorithm' => 'ECDH-ES+A256KW',
            '--now' => true,
        ]);

        // When
        $tester = self::console('beffroi:keys:retire', [
            'kid' => $first,
            '--force' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame(KeyStatus::Retired, self::key($first)->status);
        static::assertNotContains($first, self::publishedKids());
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function anAlgorithmTheProviderDoesNotSignWithIsRefused(): void
    {
        // When
        $tester = self::console('beffroi:keys:rotate', [
            '--algorithm' => 'HS256',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('does not sign with "HS256"', self::flattened($tester));
    }

    #[Test]
    public function aRotationStagesAKeyNextToTheActiveOne(): void
    {
        // Given
        $active = self::displayed(self::console('beffroi:keys:rotate'), 'Key identifier');

        // When
        $tester = self::console('beffroi:keys:rotate');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $staged = self::displayed($tester, 'Key identifier');
        static::assertSame('staged', self::displayed($tester, 'Status'));
        $list = self::flattened(self::console('beffroi:keys:list'));
        static::assertMatchesRegularExpression(sprintf('/Key identifier\s+%s\s+Algorithm\s+RS256\s+Use\s+sig\s+Status\s+active\s+/', $active), $list);
        static::assertMatchesRegularExpression(sprintf('/Key identifier\s+%s\s+Algorithm\s+RS256\s+Use\s+sig\s+Status\s+staged\s+/', $staged), $list);
        static::assertSame(KeyStatus::Active, self::key($active)->status);
    }

    #[Test]
    public function theStagedKeySaysWhenItActivates(): void
    {
        // Given
        self::console('beffroi:keys:rotate');
        $staged = self::key(self::displayed(self::console('beffroi:keys:rotate'), 'Key identifier'));

        // When
        $tester = self::console('beffroi:keys:list');

        // Then
        static::assertEquals($staged->createdAt->modify(self::STAGING_DELAY), $staged->activationDueAt);
        static::assertMatchesRegularExpression(
            sprintf(
                '/Key identifier\s+%s\s+.*?Activates at\s+%s/',
                $staged->kid,
                preg_quote($staged->activationDueAt->format(DateTimeInterface::RFC3339), '/'),
            ),
            self::flattened($tester),
        );
    }

    #[Test]
    public function aRotationTellsTheOperatorWhenTheStagedKeySigns(): void
    {
        // Given
        self::console('beffroi:keys:rotate');

        // When
        $tester = self::console('beffroi:keys:rotate');

        // Then
        $staged = self::key(self::displayed($tester, 'Key identifier'));
        static::assertStringContainsString(
            sprintf('the scheduled step activates the new key at %s', $staged->activationDueAt->format(DateTimeInterface::RFC3339)),
            self::flattened($tester),
        );
        static::assertStringContainsString(sprintf('"beffroi:keys:activate %s" does it earlier', $staged->kid), self::flattened($tester));
    }

    #[Test]
    public function aRotationNowActivatesAtOnceAndStartsRetiringThePreviousKey(): void
    {
        // Given
        $previous = self::displayed(self::console('beffroi:keys:rotate'), 'Key identifier');

        // When
        $tester = self::console('beffroi:keys:rotate', [
            '--now' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('active', self::displayed($tester, 'Status'));
        static::assertStringContainsString(sprintf('The key "%s" was active and is now retiring', $previous), self::flattened($tester));
        static::assertSame(KeyStatus::Retiring, self::key($previous)->status);
        static::assertStringContainsString(
            sprintf('until %s', self::key($previous)->retirementDueAt?->format(DateTimeInterface::RFC3339)),
            self::flattened($tester),
        );
    }

    #[Test]
    public function aRotationForACompromiseRetiresThePreviousKeyAtOnce(): void
    {
        // Given
        $compromised = self::displayed(self::console('beffroi:keys:rotate'), 'Key identifier');

        // When
        $tester = self::console('beffroi:keys:rotate', [
            '--compromised' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('active', self::displayed($tester, 'Status'));
        static::assertStringContainsString(sprintf('The key "%s" was active and is retired at once', $compromised), self::flattened($tester));
        static::assertSame(KeyStatus::Retired, self::key($compromised)->status);
        static::assertSame([self::displayed($tester, 'Key identifier')], self::publishedKids());
        [$retired] = self::events(TenantKeyRetired::class);
        static::assertSame(RetirementReason::Compromised, $retired->reason);
    }

    #[Test]
    public function activatingAStagedKeyByHandEndsItsStagingWindow(): void
    {
        // Given
        $previous = self::displayed(self::console('beffroi:keys:rotate'), 'Key identifier');
        $staged = self::displayed(self::console('beffroi:keys:rotate'), 'Key identifier');

        // When
        $tester = self::console('beffroi:keys:activate', [
            'kid' => $staged,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('active', self::displayed($tester, 'Status'));
        static::assertStringContainsString(sprintf('The key "%s" was active and is now retiring', $previous), self::flattened($tester));
        static::assertSame(KeyStatus::Active, self::key($staged)->status);
        static::assertSame(KeyStatus::Retiring, self::key($previous)->status);
        static::assertStringContainsString(
            sprintf('until %s', self::key($previous)->retirementDueAt?->format(DateTimeInterface::RFC3339)),
            self::flattened($tester),
        );
    }

    /**
     * @param array<string, string|bool> $input
     */
    #[Test]
    #[DataProvider('provideActivationsRefused')]
    public function whatIsNotAStagedKeyIsNotActivated(array $input, string $message): void
    {
        // Given
        $active = self::displayed(self::console('beffroi:keys:rotate'), 'Key identifier');

        // When
        $tester = self::console('beffroi:keys:activate', array_map(static fn (string|bool $value): string|bool => $value === '{active}'
            ? $active
            : $value, $input));

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
        yield 'unknown key' => [
            [
                'kid' => 'nope',
            ],
            'has no key "nope"',
        ];
        yield 'the active key' => [
            [
                'kid' => '{active}',
            ],
            'Only a staged key can be activated; this one is active.',
        ];
    }

    #[Test]
    public function retiringAKeyInsideItsWindowIsRefusedWithoutForce(): void
    {
        // Given
        $retiring = self::retiringKey();

        // When
        $tester = self::console('beffroi:keys:retire', [
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
        $tester = self::console('beffroi:keys:retire', [
            'kid' => $retiring,
            '--force' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('retired', self::displayed($tester, 'Status'));
        static::assertStringContainsString('before its retirement date', self::flattened($tester));
        static::assertSame(KeyStatus::Retired, self::key($retiring)->status);
        static::assertSame(RetirementReason::Forced, self::events(TenantKeyRetired::class)[0]->reason);
    }

    /**
     * @param array<string, string|bool> $input
     */
    #[Test]
    #[DataProvider('provideRetirementsRefused')]
    public function whatIsNotARetiringKeyIsNotRetired(array $input, int $status, string $message): void
    {
        // Given
        $active = self::displayed(self::console('beffroi:keys:rotate'), 'Key identifier');

        // When
        $tester = self::console('beffroi:keys:retire', array_map(static fn (string|bool $value): string|bool => $value === '{active}'
            ? $active
            : $value, $input));

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
        yield 'unknown key' => [
            [
                'kid' => 'nope',
                '--force' => true,
            ],
            Command::FAILURE,
            'has no key "nope"',
        ];
        yield 'the active key' => [
            [
                'kid' => '{active}',
                '--force' => true,
            ],
            Command::FAILURE,
            'The active key cannot be retired; rotate first.',
        ];
        yield 'a key and --due' => [
            [
                'kid' => '{active}',
                '--due' => true,
            ],
            Command::INVALID,
            'not both, not neither',
        ];
        yield 'neither a key nor --due' => [[], Command::INVALID, 'not both, not neither'];
    }

    #[Test]
    public function retiringTheDueKeysLeavesTheOneInsideItsWindow(): void
    {
        // Given
        $due = self::keyPastItsRetirementDate();
        $insideItsWindow = self::retiringKey();

        // When
        $tester = self::console('beffroi:keys:retire', [
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
        $tester = self::console('beffroi:keys:retire', [
            '--due' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('No key of "default" is past its retirement date.', self::flattened($tester));
    }

    #[Test]
    public function theListShowsARetiredKeyOnRequestOnly(): void
    {
        // Given
        $retired = self::keyPastItsRetirementDate();
        self::console('beffroi:keys:retire', [
            '--due' => true,
        ]);

        // When
        $published = self::flattened(self::console('beffroi:keys:list'));
        $all = self::flattened(self::console('beffroi:keys:list', [
            '--all' => true,
        ]));

        // Then
        static::assertStringNotContainsString($retired->kid, $published);
        static::assertMatchesRegularExpression(
            sprintf(
                '/Key identifier\s+%s\s+Algorithm\s+RS256\s+Use\s+sig\s+Status\s+retired\s+Created at\s+\S+\s+Activated at\s+\S+\s+Retiring since\s+\S+\s+Retirement due at\s+\S+\s+Retired at\s+2026-\S+/',
                $retired->kid,
            ),
            $all,
        );
    }

    #[Test]
    public function theCheckSaysTheActiveKeyOpensWithTheKms(): void
    {
        // Given
        self::console('beffroi:keys:rotate');

        // When
        $tester = self::console('beffroi:keys:list', [
            '--check' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('yes', self::displayed($tester, 'Opens with the KMS'));
    }

    #[Test]
    public function theCheckFailsOnAKeyTheKmsCannotOpen(): void
    {
        // Given
        $dead = self::stagedKeySealedUnderAnotherMasterKey();

        // When
        $tester = self::console('beffroi:keys:list', [
            '--check' => true,
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringStartsWith('no: The sealed key could not be opened.', self::displayed($tester, 'Opens with the KMS'));
        static::assertStringContainsString(sprintf('The KMS cannot open the key %s (RS256) of "default"', $dead->kid), self::flattened($tester));
        static::assertStringContainsString('a rotation publishes a key sealed under the master key the KMS has now', self::flattened($tester));
        static::assertStringContainsString('beffroi:keys:rotate --now --algorithm=RS256', self::flattened($tester));
        static::assertSame(KeyStatus::Staged, self::key($dead->kid)->status);
    }

    #[Test]
    public function everyDeadKeyNamesTheRotationThatReachesIt(): void
    {
        // Given
        $signing = self::stagedKeySealedUnderAnotherMasterKey();
        $elliptic = self::stagedKeySealedUnderAnotherMasterKey(Algorithms::es256());

        // When
        $tester = self::console('beffroi:keys:list', [
            '--check' => true,
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        $said = self::flattened($tester);
        static::assertStringContainsString(sprintf('%s (RS256)', $signing->kid), $said);
        static::assertStringContainsString(sprintf('%s (ES256)', $elliptic->kid), $said);
        static::assertStringContainsString('beffroi:keys:rotate --now --algorithm=RS256', $said);
        static::assertStringContainsString('beffroi:keys:rotate --now --algorithm=ES256', $said);
    }

    #[Test]
    public function twoDeadKeysOfOneAlgorithmNameOneRotation(): void
    {
        // Given
        self::stagedKeySealedUnderAnotherMasterKey();
        self::stagedKeySealedUnderAnotherMasterKey();

        // When
        $tester = self::console('beffroi:keys:list', [
            '--check' => true,
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame(1, preg_match_all('/--algorithm=RS256/', self::flattened($tester)));
    }

    /**
     * Architecture §3.3
     */
    #[Test]
    public function theCheckLeavesARetiringKeyClosed(): void
    {
        // Given
        $retiring = self::retiringKey();

        // When
        $tester = self::console('beffroi:keys:list', [
            '--check' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame(
            1,
            preg_match(
                sprintf('/Key identifier\s+%s\s+Algorithm\s+RS256\s+Use\s+sig\s+Status\s+retiring\s+(.*?)Key identifier/', $retiring),
                self::flattened($tester),
                $matches,
            ),
            self::flattened($tester),
        );
        static::assertStringNotContainsString('Opens with the KMS', $matches[1]);
        static::assertMatchesRegularExpression(
            '/Status\s+active\s+Created at\s+\S+\s+Activated at\s+\S+\s+Opens with the KMS\s+yes/',
            self::flattened($tester),
        );
    }

    #[Test]
    public function theScheduledStepActivatesAStagedKeyWhoseDelayElapsed(): void
    {
        // Given
        $previous = self::activeKeyCreatedTenMinutesAgo();
        $due = self::stagedKeyDated(self::currentSecond()->modify('-4 minutes'), self::currentSecond()->modify('-1 minute'));

        // When
        self::tick();

        // Then
        static::assertSame(KeyStatus::Active, self::key($due->kid)->status);
        static::assertSame(KeyStatus::Retiring, self::key($previous)->status);
    }

    #[Test]
    public function theScheduledStepLeavesAStagedKeyInsideItsWindow(): void
    {
        // Given
        $active = self::displayed(self::console('beffroi:keys:rotate'), 'Key identifier');
        $staged = self::displayed(self::console('beffroi:keys:rotate'), 'Key identifier');

        // When
        self::tick();

        // Then
        static::assertSame(KeyStatus::Staged, self::key($staged)->status);
        static::assertSame(KeyStatus::Active, self::key($active)->status);
    }

    /**
     * Decision 0020
     */
    #[Test]
    public function theScheduledStepLeavesADueMessageKeyThatAFailedMessageIsSealedTo(): void
    {
        // Given
        $key = self::keyPastItsRetirementDate(Algorithms::messageSeal());
        self::failedMessageSealedTo($key);

        // When
        self::tick();

        // Then
        static::assertSame(KeyStatus::Retiring, self::key($key->kid)->status);
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

    #[Test]
    public function theScheduledStepNamesItselfInTheEvents(): void
    {
        // Given
        self::activeKeyCreatedTenMinutesAgo();
        self::stagedKeyDated(self::currentSecond()->modify('-4 minutes'), self::currentSecond()->modify('-1 minute'));

        // When
        self::tick();

        // Then
        [, $rotated] = self::events(TenantKeyRotated::class);
        static::assertNull($rotated->context->ipAddress);
        static::assertStringStartsWith('beffroi-scheduler/beffroi (', $rotated->context->userAgent ?? '');
    }

    #[Test]
    public function theScheduledStepDoesNothingWithoutATenant(): void
    {
        // Given
        self::entityManager()->getConnection()->executeStatement('DELETE FROM beffroi_tenant');
        self::reload();

        // When
        self::tick();

        // Then
        static::assertSame([], self::events(TenantKeyRotated::class));
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function theScheduleOfTheProviderCarriesTheStepEveryMinute(): void
    {
        // When
        $tester = self::console('debug:scheduler');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('beffroi', $tester->getDisplay());
        static::assertStringContainsString('every 1 minute', $tester->getDisplay());
        static::assertStringContainsString(AdvanceKeyLifecycle::class, $tester->getDisplay());
    }

    /**
     * Decision 0009
     */
    #[Test]
    public function theScheduleCarriesTheRemovalOfTheClientsNobodyUses(): void
    {
        // When
        $tester = self::console('debug:scheduler');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(RemoveUnusedClients::class, $tester->getDisplay());
        static::assertStringContainsString('every 1 hour', $tester->getDisplay());
    }

    #[Test]
    public function theConsoleNamesItselfAndTheOperatorInTheEvents(): void
    {
        // When
        self::console('beffroi:keys:rotate');

        // Then
        [$staged] = self::events(TenantKeyStaged::class);
        static::assertNull($staged->context->ipAddress);
        static::assertMatchesRegularExpression('/^beffroi-console\/beffroi:keys:rotate \([^@]+@.+\)$/', $staged->context->userAgent ?? '');
    }

    #[Test]
    public function theScheduledStepStagesASuccessorForAKeyPastItsAge(): void
    {
        // Given
        $old = self::keyPastItsAge();

        // When
        self::tick();

        // Then
        static::assertSame(KeyStatus::Active, self::key($old->kid)->status);
        static::assertCount(1, self::stagedKeys());
        static::assertSame('RS256', self::stagedKeys()[0]->algorithm->name());
    }

    #[Test]
    public function theScheduledStepStagesOneSuccessorAndNotOnePerTick(): void
    {
        // Given
        self::keyPastItsAge();
        self::tick();

        // When
        self::tick();

        // Then
        static::assertCount(1, self::stagedKeys());
    }

    #[Test]
    public function theScheduledStepLeavesAKeyInsideItsAge(): void
    {
        // Given
        self::console('beffroi:keys:rotate');

        // When
        self::tick();

        // Then
        static::assertSame([], self::stagedKeys());
    }

    #[Test]
    public function theCheckFailsOnAKeyThatWorkedPastItsAgeWithNothingStaged(): void
    {
        // Given
        $old = self::keyPastItsAge();

        // When
        $tester = self::console('beffroi:keys:list', [
            '--check' => true,
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('yes, and nothing is staged', self::displayed($tester, 'Has worked past its age'));
        static::assertStringContainsString($old->kid, $tester->getDisplay());
        static::assertStringContainsString('worker that is not consuming the schedule', self::flattened($tester));
    }

    #[Test]
    public function theCheckPassesOnAKeyPastItsAgeWhoseSuccessorIsStaged(): void
    {
        // Given
        self::keyPastItsAge();
        self::tick();

        // When
        $tester = self::console('beffroi:keys:list', [
            '--check' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('yes, and a successor is staged', self::displayed($tester, 'Has worked past its age'));
    }

    private static function tick(): void
    {
        self::service('test.beffroi.command_bus', MessageBusInterface::class)->dispatch(new AdvanceKeyLifecycle());
    }

    private static function activeKeyCreatedTenMinutesAgo(): string
    {
        self::mockTime(self::currentSecond()->modify('-10 minutes'));
        $kid = self::displayed(self::console('beffroi:keys:rotate'), 'Key identifier');
        self::mockTime(self::currentSecond());

        return $kid;
    }

    private static function retiringKey(): string
    {
        $kid = self::displayed(self::console('beffroi:keys:rotate'), 'Key identifier');
        self::console('beffroi:keys:rotate', [
            '--now' => true,
        ]);

        return $kid;
    }

    private static function keyPastItsRetirementDate(?KeyAlgorithmInterface $algorithm = null): TenantKey
    {
        $yesterday = self::currentSecond()->modify('-1 day');
        $key = self::stagedKeyDated($yesterday->modify('-1 hour'), $yesterday->modify('-1 hour'), $algorithm);
        $key->activate($yesterday->modify('-1 hour'));
        $key->startRetiring($yesterday, $yesterday->modify('+10 minutes'));
        self::keys()->save($key);

        return $key;
    }

    private static function stagedKeySealedUnderAnotherMasterKey(?KeyAlgorithmInterface $algorithm = null): TenantKey
    {
        $algorithm ??= Algorithms::rs256();
        $pair = self::service('test.beffroi.key_pair_generator', KeyPairGeneratorInterface::class)->generate($algorithm);
        $sealer = new EnvelopeKeySealer(new EnvelopeEncrypter(new SodiumKms(new InMemoryKeyLoader([
            'signing' => random_bytes(32),
        ]))), 'signing');
        $key = new TenantKey(
            $pair->kid,
            self::tenant(),
            $algorithm,
            $pair->publicJwk,
            $sealer->seal(self::tenant(), $pair->privateJwk),
            self::currentSecond(),
            self::currentSecond()->modify(self::STAGING_DELAY),
        );
        self::keys()->save($key);

        return $key;
    }

    private static function stagedKeyDated(
        DateTimeImmutable $createdAt,
        DateTimeImmutable $activationDueAt,
        ?KeyAlgorithmInterface $algorithm = null,
    ): TenantKey {
        $algorithm ??= Algorithms::rs256();
        $pair = self::service('test.beffroi.key_pair_generator', KeyPairGeneratorInterface::class)->generate($algorithm);
        $sealed = self::service('test.beffroi.key_sealer', KeySealerInterface::class)->seal(self::tenant(), $pair->privateJwk);
        $key = new TenantKey($pair->kid, self::tenant(), $algorithm, $pair->publicJwk, $sealed, $createdAt, $activationDueAt);
        self::keys()->save($key);

        return $key;
    }

    private static function failedMessageSealedTo(TenantKey $key): void
    {
        $seal = Algorithms::messageSeal();
        $body = new CompactSerializer()->serialize(
            new JWEBuilder(new AlgorithmManager([$seal->keyEncryption()->joseAlgorithm(), $seal->contentEncryption()->joseAlgorithm()]))
                ->create()
                ->withPayload('a:0:{}')
                ->withSharedProtectedHeader([
                    'alg' => $seal->keyEncryption()->name(),
                    'enc' => $seal->contentEncryption()->name(),
                    'kid' => $key->kid,
                    SealedMessageBody::TENANT_HEADER => self::tenant()->slug,
                ])
                ->addRecipient(new JWK([
                    ...$key->publicJwk,
                    'alg' => $seal->keyEncryption()->name(),
                ]))
                ->build(),
        );
        QueuedBodies::send(self::service('doctrine.dbal.default_connection', Connection::class), MessengerContract::FAILURE_DSN, $body);
    }

    private static function keyPastItsAge(): TenantKey
    {
        $activated = self::currentSecond()->modify('-91 days');
        $key = self::stagedKeyDated($activated, $activated);
        $key->activate($activated);
        self::keys()->save($key);

        return $key;
    }

    /**
     * @return list<TenantKey>
     */
    private static function stagedKeys(): array
    {
        return array_values(array_filter(
            self::keys()->findInService(self::tenant()),
            static fn (TenantKey $key): bool => $key->status === KeyStatus::Staged,
        ));
    }

    private static function key(string $kid): TenantKey
    {
        return self::keys()->find(self::tenant(), $kid) ?? static::fail(sprintf('The key "%s" is not stored.', $kid));
    }

    /**
     * @return list<string>
     */
    private static function publishedKids(): array
    {
        return array_map(static fn (TenantKey $key): string => $key->kid, self::keys()->findInService(self::tenant()));
    }

    private static function keys(): TenantKeyRepositoryInterface
    {
        return self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class);
    }
}
