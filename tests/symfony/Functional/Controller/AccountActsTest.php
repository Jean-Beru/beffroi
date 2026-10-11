<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use function array_map;
use function array_values;
use Beffroi\Bundle\Http\AskedPage;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\ActsOfAnAccount;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Port\JournalInterface;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sort;
use function str_starts_with;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Issues #454 and #571, architecture §5.2: what the journal holds of one person, on the page of their
 * account. Every act of the account is on it and each says what it is by its own name; the refusals are
 * there as much as the successes, because a line somebody does not recognise is what the page is for.
 */
final class AccountActsTest extends BrowserTestCase
{
    /**
     * The acceptance of the issue: a second factor accepted, a session that ended, a credential enrolled
     * or revoked, a password changed and a set of backup codes renewed were in the table and on no page.
     * Each is named in the language of the browser (architecture §5.7), and an act one of the catalogues
     * of the bundle does not name fails the kernel of this suite (StrictTranslator), so a page that
     * renders is a page where every one of them is named in that language.
     */
    #[Test]
    #[DataProvider('provideLanguages')]
    public function everyActOfAnAccountIsOnThePageAndNamesItself(string $language): void
    {
        // Given
        $alice = self::user('alice');
        foreach (ActsOfAnAccount::NAMES as $act) {
            self::record($alice, $act);
        }
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->actsPage(language: $language);

        // Then
        static::assertSame(self::sorted(ActsOfAnAccount::NAMES), self::sorted($page->filter('tbody tr')->extract(['data-act'])));
        foreach ($page->filter('tbody tr > td:first-of-type')->extract(['_text']) as $named) {
            static::assertFalse(str_starts_with(self::string($named), 'act.'), 'An act is named and never shown by its key.');
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLanguages(): iterable
    {
        yield 'a browser in English' => ['en-US,en;q=0.9'];
        yield 'a browser in French' => ['fr-FR,fr;q=0.9'];
    }

    /**
     * Issues #588 to #590: the journal of a person holds the protocol as well, a token issued in their
     * name being an act of theirs. It is read where it means something, beside what that application was
     * given, and this page is what happened to the account.
     */
    #[Test]
    public function anActOfTheProtocolIsNotOnThePageOfTheAccount(): void
    {
        // Given
        $alice = self::user('alice');
        self::record($alice, TokensIssued::NAME, 'oidc-demo');
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        static::assertCount(1, $page->filter('table[data-acts="0"] tr[data-empty]'));
    }

    #[Test]
    public function thePageShowsASignInThatSucceeded(): void
    {
        // Given
        $alice = self::user('alice');
        $session = self::session($alice, self::currentSecond());
        self::announce(new UserAuthenticated($session));
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        static::assertSame('1', $page->filter('table[data-acts]')->attr('data-acts'));
        static::assertSame([UserAuthenticated::NAME], $page->filter('tbody tr')->extract(['data-act']));
    }

    #[Test]
    public function thePageShowsAnAttemptThatWasRefused(): void
    {
        // Given
        $alice = self::user('alice');
        self::announce(self::refusedFor($alice));
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        static::assertSame([AuthenticationFailed::NAME], $page->filter('tbody tr')->extract(['data-act']));
    }

    /**
     * An act of somebody else is not on the page of this person: the journal is read by the subject of the
     * session the browser holds and never by anything the request carries.
     */
    #[Test]
    public function theActsOfSomebodyElseAreNotOnIt(): void
    {
        // Given
        $alice = self::user('alice');
        $bob = self::user('bob', 'bob-subject');
        self::announce(new UserAuthenticated(self::session($bob, self::currentSecond())));
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        static::assertCount(1, $page->filter('table[data-acts="0"] tr[data-empty]'));
    }

    #[Test]
    public function aPersonWithNothingRecordedIsToldSo(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->actsPage();

        // Then
        static::assertCount(1, $page->filter('table[data-acts="0"] tr[data-empty]'));
    }

    /**
     * The days asked for and not the whole journal (AskedPeriod): a reader looking for one afternoon in a
     * journal of a year is reading a stretch of time and not a page number.
     */
    #[Test]
    public function onlyTheActsOfTheDaysAskedForAreOnIt(): void
    {
        // Given
        $alice = self::user('alice');
        self::record($alice, UserAuthenticated::NAME, occurredAt: self::currentSecond()->modify('-20 days'));
        self::record($alice, AuthenticationFailed::NAME);
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->actsPage(from: self::day('-10 days'), to: self::day('now'));

        // Then
        static::assertSame([AuthenticationFailed::NAME], $page->filter('tbody tr')->extract(['data-act']));
    }

    /**
     * The journal of a person grows without end, so the page reads one page of it and says where the rest
     * is: as many rows as a page of a table of this plane holds, and the way to the next one.
     */
    #[Test]
    public function thePageReadsOnePageOfTheJournalAndSaysWhereTheRestIs(): void
    {
        // Given
        $alice = self::user('alice');
        self::announceRefusals($alice, AskedPage::ROWS + 1);
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        static::assertCount(AskedPage::ROWS, $page->filter('tbody tr[data-act]'));
        static::assertSame('/account/acts?page=2', $page->filter('a[data-pager="next"]')->attr('href'));
    }

    #[Test]
    public function theLastPageOfTheJournalHoldsWhatIsLeftOfIt(): void
    {
        // Given
        $alice = self::user('alice');
        self::announceRefusals($alice, AskedPage::ROWS + 1);
        $this->signIn($alice);

        // When
        $page = $this->actsPage(2);

        // Then
        static::assertCount(1, $page->filter('tbody tr[data-act]'));
        static::assertCount(0, $page->filter('a[data-pager="next"]'));
    }

    /**
     * A page past the last one is the last one: a link somebody kept, or a number they typed, reads rows
     * and never an empty table under a count that says there are some.
     */
    #[Test]
    public function aPagePastTheLastOneIsTheLastOne(): void
    {
        // Given
        $alice = self::user('alice');
        self::announceRefusals($alice, AskedPage::ROWS + 1);
        $this->signIn($alice);

        // When
        $page = $this->actsPage(99);

        // Then
        static::assertSame('2', $page->filter('nav[data-pager]')->attr('data-pager'));
        static::assertCount(1, $page->filter('tbody tr[data-act]'));
    }

    /**
     * A control that can do nothing is a control nobody should have to read.
     */
    #[Test]
    public function aJournalThatFitsOnOnePageCarriesNoControl(): void
    {
        // Given
        $alice = self::user('alice');
        self::announce(self::refusedFor($alice));
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        static::assertCount(0, $page->filter('nav[data-pager]'));
    }

    #[Test]
    public function aBrowserWithNoSessionIsRefused(): void
    {
        // When
        $this->browser->request('GET', '/account/acts');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    private function actsPage(?int $number = null, ?string $from = null, ?string $to = null, ?string $language = null): Crawler
    {
        $asked = [];
        if ($number !== null) {
            $asked['page'] = (string) $number;
        }
        if ($from !== null) {
            $asked['from'] = $from;
        }
        if ($to !== null) {
            $asked['to'] = $to;
        }
        $page = $this->browser->request(
            'GET',
            '/account/acts',
            $asked,
            server: $language === null
                ? []
                : [
                    'HTTP_ACCEPT_LANGUAGE' => $language,
                ],
        );
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return $page;
    }

    /**
     * One act of that person written straight into the journal: every act of an account is one row of four
     * facts and two names, whatever raised it, and the page reads rows.
     */
    private static function record(User $user, string $act, ?string $client = null, ?DateTimeImmutable $occurredAt = null): void
    {
        self::service('test.beffroi.journal', JournalInterface::class)
            ->record(new JournalEntry(
                Uuid::v7(),
                $user->tenant,
                $act,
                $occurredAt ?? self::currentSecond(),
                self::context(),
                $user->subject,
                $client,
            ));
    }

    /**
     * A day as the query string of the page carries one, on the clock of the deployment, which is the one
     * a person with no zone of their own reads (UserTimeZone).
     */
    private static function day(string $moment): string
    {
        return new DateTimeImmutable($moment)->format('Y-m-d');
    }

    /**
     * @param array<array-key, mixed> $names
     *
     * @return list<string>
     */
    private static function sorted(array $names): array
    {
        $sorted = array_map(self::string(...), array_values($names));
        sort($sorted);

        return $sorted;
    }

    /**
     * That many attempts refused in the name of that person, which is a journal of that many rows.
     */
    private static function announceRefusals(User $user, int $howMany): void
    {
        $bus = self::service('event.bus', MessageBusInterface::class);
        for ($refused = 0; $refused < $howMany; ++$refused) {
            $bus->dispatch(self::refusedFor($user));
        }
        self::reload();
    }

    private static function refusedFor(User $user): AuthenticationFailed
    {
        return new AuthenticationFailed(
            self::currentSecond(),
            $user->tenant,
            self::context(),
            null,
            AuthenticationFailureReason::InvalidCredential,
            $user->username,
            $user,
        );
    }

    private static function announce(DomainEventInterface $event): void
    {
        self::service('event.bus', MessageBusInterface::class)->dispatch($event);
        self::reload();
    }
}
