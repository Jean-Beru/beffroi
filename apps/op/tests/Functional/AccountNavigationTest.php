<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * The skeleton every page of the account is served in, which is this application's and not the bundle's
 * (templates/layout/account.html.twig): the column of the pages of the account, the trail at the head of a
 * page, and the bar that carries who the browser is signed in as and the way out.
 *
 * What each page says is judged by the suite of the bundle. What is here is what only this kernel can
 * answer: that the pages the bundle wires are all reachable from every one of them, and said once.
 */
final class AccountNavigationTest extends BrowserTestCase
{
    /**
     * The one rule of the arrangement (App\Account\AccountNavigation): the pages are the sections that are
     * wired, under the headings this application reads them under, and a page no heading names is in the
     * column all the same, last. A section added to the bundle is red here until it is arranged, and never
     * a page nobody can reach.
     */
    #[Test]
    public function everyPageOfTheAccountIsInTheColumnOfPages(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $page = $this->accountPage('/account');

        // Then
        static::assertSame([
            '/account',
            '/account/approvals',
            '/account/profile',
            '/account/archive',
            '/account/passkeys',
            '/account/two-factor',
            '/account/notifications',
            '/account/sessions',
            '/account/consents',
            '/account/sign-ins',
        ], $page->filter('#layout-sidebar-pages a')->extract(['href']));
    }

    #[Test]
    public function aGroupOfPagesNamesTheHeadingItIsReadUnder(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $page = $this->accountPage('/account');

        // Then
        static::assertSame(
            ['Your record', 'How you sign in', 'What has happened'],
            $page->filter('#layout-sidebar-pages ul[aria-label]')->extract(['aria-label']),
        );
    }

    #[Test]
    public function thePageBeingReadSaysSoInTheColumnOfPages(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $page = $this->accountPage('/account/sessions');

        // Then
        static::assertSame(
            ['/account/sessions'],
            $page->filter('#layout-sidebar-pages a[aria-current="page"]')->extract(['href']),
        );
    }

    /**
     * The way back is the trail at the head of the page and not a link of its own: a page of this plane
     * hangs from the home of the account, which is where the link the pages of the bundle include goes.
     */
    #[Test]
    public function theHeadOfAPageSaysWhereTheReaderIs(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $page = $this->accountPage('/account/sessions');

        // Then
        static::assertSame(
            ['Your account', 'Where you are signed in'],
            $page->filter('header[data-page-header] nav li')->each(static fn (Crawler $item): string => $item->text()),
        );
        static::assertCount(0, $page->filter('a[data-back]'));
    }

    /**
     * Issue beffroi-php/op#17 and what this skeleton adds to it: the identity of the reader and the way out
     * are true of every page of the plane, so they are in the bar above them and on none of them.
     */
    #[Test]
    public function whoIsSignedInAndTheWayOutAreInTheBarAndNotOnThePage(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $page = $this->accountPage('/account');

        // Then
        static::assertCount(1, $page->filter('#layout-topbar div[data-control="user"] a[href="/logout"]'));
        static::assertCount(0, $page->filter('main a[href="/logout"]'));
    }

    /**
     * The controls of the bar share one group of radio buttons and one veil (templates/layout/_control.html
     * .twig), which is what makes one of them open at a time and a click anywhere else close it: the page
     * runs no script, so the shape is the behaviour and a page that lost it would look the same.
     */
    #[Test]
    public function theControlsOfTheBarShareOneGroupAndOneVeil(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $page = $this->accountPage('/account');

        // Then
        $panels = $page->filter('#layout-topbar div[data-control] > div[data-control="panel"]')->count();
        static::assertSame($panels + 1, $page->filter('#layout-topbar input[name="layout-control"]')->count());
        static::assertCount(1, $page->filter('#layout-topbar input[name="layout-control"][checked]'));
        static::assertCount(1, $page->filter('#layout-topbar input#layout-control-none[checked]'));
        static::assertCount(1, $page->filter('#layout-topbar label[for="layout-control-none"][data-control="veil"]'));
    }

    /**
     * The action a page offers is beside its title, wherever the page of the bundle writes it: setting up an
     * authenticator app is what the page of the second factor offers, and it is read there and not under
     * the two paragraphs that say the account holds none.
     */
    #[Test]
    public function theActionOfAPageIsReadBesideItsTitle(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $page = $this->accountPage('/account/two-factor');

        // Then
        static::assertCount(1, $page->filter('header[data-page-header] form[data-two-factor="begin"]'));
    }

    private function accountPage(string $path): Crawler
    {
        $page = $this->browser->request('GET', $path);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), (string) $response->getContent());

        return $page;
    }
}
