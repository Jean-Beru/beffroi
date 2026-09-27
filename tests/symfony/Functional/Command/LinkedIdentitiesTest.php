<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Command;

use Heidi\Core\Port\LinkedIdentityRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;

/**
 * Decision 0002: the identities a user has at an upstream provider, written from the console. What needs them
 * today is the JWT bearer grant (RFC 7523 §3), whose subjects are users of this tenant through these rows and
 * through nothing else.
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
        $tester = self::console('heidi:user:link', [
            'username' => 'alice',
            'provider' => self::PROVIDER,
            'subject' => self::SUBJECT,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $identity = self::service('test.heidi.linked_identities', LinkedIdentityRepositoryInterface::class)
            ->find(self::tenant(), self::PROVIDER, self::SUBJECT);
        static::assertNotNull($identity);
        static::assertSame('alice', $identity->user->username);
    }

    /**
     * What a second run of a provisioning task does: the row that was there, not a second one.
     */
    #[Test]
    public function theSameIdentityLinkedAgainKeepsTheRowItAlreadyHas(): void
    {
        // Given
        self::userWithPassword('alice', 'correct horse battery staple');
        $first = self::displayed(self::console('heidi:user:link', [
            'username' => 'alice',
            'provider' => self::PROVIDER,
            'subject' => self::SUBJECT,
        ]), 'Identifier');

        // When
        $tester = self::console('heidi:user:link', [
            'username' => 'alice',
            'provider' => self::PROVIDER,
            'subject' => self::SUBJECT,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame($first, self::displayed($tester, 'Identifier'));
    }

    /**
     * Decision 0002: a subject names one user of a tenant, or a sign-in at that provider would be worth two
     * accounts.
     */
    #[Test]
    public function anIdentityAnotherUserAlreadyIsCannotBeMoved(): void
    {
        // Given
        self::userWithPassword('alice', 'correct horse battery staple');
        self::userWithPassword('bob', 'correct horse battery staple');
        self::console('heidi:user:link', [
            'username' => 'alice',
            'provider' => self::PROVIDER,
            'subject' => self::SUBJECT,
        ]);

        // When
        $tester = self::console('heidi:user:link', [
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
        $tester = self::console('heidi:user:link', [
            'username' => 'nobody',
            'provider' => self::PROVIDER,
            'subject' => self::SUBJECT,
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('There is no user named "nobody"', self::flattened($tester));
    }
}
