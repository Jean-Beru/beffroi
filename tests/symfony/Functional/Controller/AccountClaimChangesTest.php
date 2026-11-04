<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Http\AskedPage;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ClaimHistoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.2
 */
final class AccountClaimChangesTest extends BrowserTestCase
{
    #[Test]
    public function thePageShowsWhatThePersonChangedWithWhatItSaidBefore(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        self::aChange($alice, 'Ada', 'Augusta');
        self::reload();

        // When
        $page = $this->changesPage();

        // Then
        static::assertSame(['nickname'], $page->filter('tbody tr[data-change]')->extract(['data-change']));
        $row = $page->filter('tbody tr[data-change]')->first()->filter('td');
        static::assertSame('Ada', $row->eq(1)->text());
        static::assertSame('Augusta', $row->eq(2)->text());
    }

    #[Test]
    public function aPersonWhoChangedNothingIsToldSo(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->changesPage();

        // Then
        static::assertCount(1, $page->filter('table[data-changes="0"] tr[data-empty]'));
    }

    #[Test]
    public function theHistoryIsReadInPages(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        for ($made = 0; $made <= AskedPage::ROWS; ++$made) {
            self::aChange($alice, 'Ada', 'Augusta');
        }
        self::reload();

        // When
        $page = $this->changesPage();

        // Then
        static::assertCount(AskedPage::ROWS, $page->filter('tbody tr[data-change]'));
        static::assertSame('/account/profile/changes?page=2', $page->filter('a[data-pager="next"]')->attr('href'));
    }

    #[Test]
    public function thePeriodNarrowsTheHistoryToTheDaysItNames(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        self::aChange($alice, 'Ada', 'Augusta');
        self::aChange($alice, 'Augusta', 'Ada', '-2 months');
        self::reload();

        // When
        $page = $this->changesPage(['from' => self::currentSecond()->format('Y-m-d')]);

        // Then
        static::assertCount(1, $page->filter('tbody tr[data-change]'));
        static::assertSame('/account/profile/changes', $page->filter('a[data-filter="clear"]')->attr('href'));
    }

    #[Test]
    public function aPeriodThatEndsBeforeItStartsNarrowsNothing(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        self::aChange($alice, 'Ada', 'Augusta');
        self::aChange($alice, 'Augusta', 'Ada', '-2 months');
        self::reload();

        // When
        $page = $this->changesPage([
            'from' => self::currentSecond()->format('Y-m-d'),
            'to' => self::currentSecond()->modify('-1 month')->format('Y-m-d'),
        ]);

        // Then
        static::assertCount(2, $page->filter('tbody tr[data-change]'));
        static::assertCount(0, $page->filter('a[data-filter="clear"]'));
    }

    #[Test]
    public function aBrowserWithNoSessionIsRefused(): void
    {
        // When
        $this->browser->request('GET', '/account/profile/changes');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * @param array<string, string> $narrowed
     */
    private function changesPage(array $narrowed = []): Crawler
    {
        $page = $this->browser->request('GET', '/account/profile/changes', $narrowed);
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return $page;
    }

    private static function aChange(User $user, ?string $was, ?string $became, string $ago = 'now'): void
    {
        $at = self::currentSecond()->modify($ago);
        self::service('test.beffroi.claim_history', ClaimHistoryInterface::class)
            ->record(new ClaimChange(Uuid::v7(), $user, 'nickname', $was, $became, $at, self::context()));
    }
}
