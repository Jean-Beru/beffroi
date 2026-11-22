<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use Beffroi\Core\Port\LinkedIdentityRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;

/**
 * Decision 0002
 */
final class LinkedIdentitiesTest extends ConsoleTestCase
{
    private const string PROVIDER = 'demo-issuer';

    private const string SUBJECT = 'alice@issuer.example';

    #[Test]
    public function theSubjectOfAProviderBecomesARowNamingTheUser(): void
    {
        // Given
        self::userWithPassword('alice', 'correct horse battery staple');

        // When
        $tester = self::console('beffroi:user:link', [
            'username' => 'alice',
            'provider' => self::PROVIDER,
            'subject' => self::SUBJECT,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $identity = self::service('test.beffroi.linked_identities', LinkedIdentityRepositoryInterface::class)
            ->find(self::tenant(), self::PROVIDER, self::SUBJECT);
        static::assertNotNull($identity);
        static::assertSame('alice', $identity->user->username);
    }

    #[Test]
    public function theSameIdentityLinkedAgainKeepsTheRowItAlreadyHas(): void
    {
        // Given
        self::userWithPassword('alice', 'correct horse battery staple');
        $first = self::displayed(self::console('beffroi:user:link', [
            'username' => 'alice',
            'provider' => self::PROVIDER,
            'subject' => self::SUBJECT,
        ]), 'Identifier');

        // When
        $tester = self::console('beffroi:user:link', [
            'username' => 'alice',
            'provider' => self::PROVIDER,
            'subject' => self::SUBJECT,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame($first, self::displayed($tester, 'Identifier'));
    }

    /**
     * Decision 0002
     */
    #[Test]
    public function anIdentityAnotherUserAlreadyIsCannotBeMoved(): void
    {
        // Given
        self::userWithPassword('alice', 'correct horse battery staple');
        self::userWithPassword('bob', 'correct horse battery staple');
        self::console('beffroi:user:link', [
            'username' => 'alice',
            'provider' => self::PROVIDER,
            'subject' => self::SUBJECT,
        ]);

        // When
        $tester = self::console('beffroi:user:link', [
            'username' => 'bob',
            'provider' => self::PROVIDER,
            'subject' => self::SUBJECT,
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('is already the user "alice"', self::flattened($tester));
    }

    #[Test]
    public function aUsernameNobodyAnswersToIsSaidAsEveryCommandSaysIt(): void
    {
        // When
        $tester = self::console('beffroi:user:link', [
            'username' => 'nobody',
            'provider' => self::PROVIDER,
            'subject' => self::SUBJECT,
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('There is no user named "nobody"', self::flattened($tester));
    }
}
