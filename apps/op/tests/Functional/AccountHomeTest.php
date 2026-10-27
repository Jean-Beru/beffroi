<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use PHPUnit\Framework\Attributes\Test;

/**
 * The home of the account as this application serves it (architecture §5.2): one card per page of the
 * account, which says the page it opens, what that page is for, and what the account holds there.
 *
 * What the pages themselves say is judged by the suite of the bundle, whose own home is a list. What is
 * here is what only this kernel can answer: that the arrangement of this application (App\Account\
 * AccountNavigation) names every page the bundle wires, and that a card carries the three things it says.
 */
final class AccountHomeTest extends BrowserTestCase
{
    #[Test]
    public function aCardSaysThePageItOpensWhatThatPageIsForAndWhatTheAccountHoldsThere(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $card = $this->accountHome()->filter('li[data-section="beffroi_interaction_account_passkeys"]');

        // Then
        static::assertCount(1, $card->filter('div[data-section-head] span[data-section-icon] svg'));
        static::assertSame('/account/passkeys', $card->filter('a')->attr('href'));
        static::assertSame('Your passkeys', $card->filter('a')->text());
        static::assertSame(
            'Signing in with your device rather than a password.',
            $card->filter('p[data-section-about]')->text(),
        );
        static::assertSame('No passkey', $card->filter('span[data-state]')->text());
    }

    /**
     * The one rule of the arrangement on this page, the counterpart of the column of pages: a page the
     * bundle wires and this application does not name would be a card with a hole in it, so a section
     * added upstream is red here until it is arranged.
     */
    #[Test]
    public function everyCardCarriesTheIconOfItsPageAndTheLineThatSaysWhatItIsFor(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $page = $this->accountHome();

        // Then
        $cards = $page->filter('ul[data-sections] li[data-section]')->count();
        static::assertGreaterThan(0, $cards);
        static::assertSame($cards, $page->filter('li[data-section] span[data-section-icon] svg')->count());
        static::assertSame($cards, $page->filter('li[data-section] p[data-section-about]')->count());
        static::assertSame($cards, $page->filter('li[data-section] span[data-state]')->count());
    }
}
