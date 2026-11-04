<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use App\Command\TenantLoginFloorCommand;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Event\CredentialForgotten;
use Beffroi\Core\Domain\Session\PhishingResistant;
use Beffroi\Core\Domain\Session\SingleFactor;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;

final class TenantLoginFloorTest extends ConsoleTestCase
{
    #[Test]
    public function theTenantNamesItsFloorAndTheCredentialsItForbidsAreForgotten(): void
    {
        // Given
        $alice = self::userWithPassword('alice', 'correct horse battery staple');
        self::forgetEvents();

        // When
        $tester = self::console(
            TenantLoginFloorCommand::NAME,
            [
                'floor' => 'phishing_resistant',
            ],
            inputs: ['yes'],
        );

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('1 credential was forgotten', self::flattened($tester));
        static::assertSame(PhishingResistant::NAME, self::tenant()->loginFloor->name());
        static::assertSame([], self::credentials()->findByUser($alice, PasswordCredential::class));
        static::assertCount(1, self::events(CredentialForgotten::class));
    }

    #[Test]
    public function aPasswordCannotBePosedOnATenantThatForbidsIt(): void
    {
        // Given
        self::user('alice');
        self::console(
            TenantLoginFloorCommand::NAME,
            [
                'floor' => 'phishing_resistant',
            ],
            inputs: ['yes'],
        );

        // When
        $tester = self::console(
            'beffroi:user:set-password',
            [
                'username' => 'alice',
                '--password-stdin' => true,
            ],
            inputs: ['correct horse battery staple'],
        );

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString(
            'A password proves no login of the tenant "default", whose logins prove "phishing_resistant" at the least',
            self::flattened($tester),
        );
    }

    private static function credentials(): CredentialRepositoryInterface
    {
        return self::service('test.beffroi.credentials', CredentialRepositoryInterface::class);
    }

    #[Test]
    public function anUnconfirmedFloorChangesNothing(): void
    {
        // Given
        $alice = self::userWithPassword('alice', 'correct horse battery staple');

        // When
        $tester = self::console(
            TenantLoginFloorCommand::NAME,
            [
                'floor' => 'phishing_resistant',
            ],
            inputs: ['no'],
        );

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertSame(SingleFactor::NAME, self::tenant()->loginFloor->name());
        static::assertCount(1, self::credentials()->findByUser($alice, PasswordCredential::class));
    }

    #[Test]
    public function aPredicateThisProviderDoesNotDefineIsRefusedWithTheOnesItDoes(): void
    {
        // When
        $tester = self::console(TenantLoginFloorCommand::NAME, [
            'floor' => 'no_password_at_all',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString(
            'This provider defines no authentication predicate "no_password_at_all"; it defines phishing_resistant_hardware, phishing_resistant, two_factors, single_factor.',
            self::flattened($tester),
        );
        static::assertSame(SingleFactor::NAME, self::tenant()->loginFloor->name());
    }

    #[Test]
    public function theFloorItAlreadyNamesIsNotAskedAgain(): void
    {
        // When
        $tester = self::console(TenantLoginFloorCommand::NAME, [
            'floor' => 'single_factor',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('already proves "single_factor" at the least', self::flattened($tester));
    }
}
