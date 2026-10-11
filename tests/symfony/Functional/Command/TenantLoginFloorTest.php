<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Command;

use Beffroi\Bundle\Command\TenantLoginFloorCommand;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Event\CredentialForgotten;
use Beffroi\Core\Domain\Session\AuthenticationPredicate;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;

/**
 * Issue #327: the floor of every login of the tenant, named from the console without a redeploy. It is
 * the command the console of the tenant will press the same use case with (epic #194), so what it does is
 * the act and not a second copy of it: the row is written and the credentials the floor forbids go.
 */
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
        static::assertSame(AuthenticationPredicate::PhishingResistant, self::tenant()->loginFloor);
        static::assertSame([], self::credentials()->findByUser($alice, PasswordCredential::class));
        static::assertCount(1, self::events(CredentialForgotten::class));
    }

    /**
     * What an administrator is told when they try to pose one anyway: the command of the password says why
     * rather than letting the refusal of the core out (issue #327).
     */
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

    /**
     * The act is irreversible for whoever held one of those credentials, so an answer that is not yes
     * changes nothing: neither the row of the tenant nor one credential.
     */
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
        static::assertSame(AuthenticationPredicate::SingleFactor, self::tenant()->loginFloor);
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
            'This provider defines no predicate "no_password_at_all"; a tenant names one of single_factor, two_factors, phishing_resistant, phishing_resistant_hardware.',
            self::flattened($tester),
        );
        static::assertSame(AuthenticationPredicate::SingleFactor, self::tenant()->loginFloor);
    }

    /**
     * The floor it already names is not an act: nothing is written, nothing is forgotten, and the command
     * says so rather than asking to confirm a sweep that would find what it swept already.
     */
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
