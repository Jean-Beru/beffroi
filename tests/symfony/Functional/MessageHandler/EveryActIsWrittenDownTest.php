<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\MessageHandler;

use Beffroi\Bundle\Tests\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\ClassifiedModel;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Event\LoadBudgetSpent;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Oidc\Domain\Event\ConsentGranted;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use function array_keys;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #454: every act of the provider is written down, off the request, with who did what, when and
 * from where, and with nothing else at all.
 *
 * That an event is named is a test of each package (EveryEventNamesItsActTest); that the handler reaches
 * every event is the interface it handles, there being no list of events anywhere to fall out of date.
 * What is tested here is what a row ends up holding, in the three shapes an act takes: one that names a
 * person, one that names a client, and one that names neither.
 */
final class EveryActIsWrittenDownTest extends DatabaseTestCase
{
    #[Test]
    public function anActThatConcernsAPersonNamesThem(): void
    {
        // Given
        $user = self::user('alice');
        $session = self::session($user, self::now());

        // When
        self::announce(new UserAuthenticated($session));

        // Then
        $act = self::onlyAct();
        static::assertSame(UserAuthenticated::NAME, $act->act);
        static::assertSame($user->subject->value, $act->subject?->value);
        static::assertNull($act->client);
    }

    #[Test]
    public function anActThatNamesNobodyLeavesThatColumnEmpty(): void
    {
        // When
        self::announce(new LoadBudgetSpent(self::now(), self::tenant(), self::context(), 'origin', '/jwks', null));

        // Then
        $act = self::onlyAct();
        static::assertSame(LoadBudgetSpent::NAME, $act->act);
        static::assertNull($act->subject);
        static::assertNull($act->client);
    }

    #[Test]
    public function anActThatConcernsAClientNamesIt(): void
    {
        // Given
        $user = self::user('alice');

        // When
        self::announce(new ConsentGranted(
            self::now(),
            self::tenant(),
            Uuid::v7(),
            'oidc-demo',
            $user->subject,
            new Scopes([new Scope('openid')]),
            null,
            null,
            self::context(),
        ));

        // Then
        $act = self::onlyAct();
        static::assertSame(ConsentGranted::NAME, $act->act);
        static::assertSame('oidc-demo', $act->client);
    }

    /**
     * The provenance of an act is what the request carried of a person, and it is read back whole from the
     * sealed column that holds it.
     */
    #[Test]
    public function anActSaysWhereItCameFrom(): void
    {
        // When
        self::announce(new AuthenticationFailed(
            self::now(),
            self::tenant(),
            self::context(),
            null,
            AuthenticationFailureReason::UnknownUser,
            'nobody',
            null,
        ));

        // Then
        $act = self::onlyAct();
        static::assertSame(SealedRows::IP_ADDRESS, $act->context->ipAddress);
        static::assertNull($act->subject, 'an authentication that failed on an identifier no account answers happened to nobody');
    }

    /**
     * What makes "no secret in the journal" a shape and not a review: the table holds the four facts and
     * the two names, and no column a caller fills with whatever it has. A column added to it is a column
     * the classification of the schema refuses until somebody declares it (SchemaClassificationTest), and
     * this is where what the journal may hold is said.
     */
    #[Test]
    public function theJournalHoldsTheFourFactsAndTheTwoNamesAndNothingElse(): void
    {
        // When / Then
        static::assertSame(
            ['act', 'client', 'context', 'id', 'occurred_at', 'subject', 'tenant_id'],
            array_keys(ClassifiedModel::of(self::entityManager())->linesOf('beffroi_journal')),
        );
    }

    private static function connection(): Connection
    {
        return self::service('doctrine.dbal.default_connection', Connection::class);
    }

    /**
     * A count read from the database, narrowed where it is read: a driver answers a number as whatever its
     * platform calls one.
     */
    private static function counted(string $sql): int
    {
        $value = self::service('doctrine.dbal.default_connection', Connection::class)->fetchOne($sql);
        static::assertIsNumeric($value);

        return (int) $value;
    }

    private static function announce(DomainEventInterface $event): void
    {
        self::service('event.bus', MessageBusInterface::class)->dispatch($event);
        self::reload();
    }

    private static function onlyAct(): JournalEntry
    {
        static::assertSame(1, self::counted('SELECT COUNT(*) FROM beffroi_journal'));
        $id = self::connection()->fetchOne('SELECT id FROM beffroi_journal');
        static::assertIsString($id);

        return self::entityManager()->find(JournalEntry::class, Uuid::fromString($id)) ?? static::fail('The act was not written down.');
    }
}
