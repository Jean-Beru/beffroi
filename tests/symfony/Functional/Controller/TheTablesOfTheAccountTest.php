<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Architecture §6, the pages: the frame is what the stylesheet scrolls, so that a table wider than the screen
 * never takes the page sideways with it, and every cell carries the heading of its column, which a phone reads
 * above the value once the line is a card.
 */
final class TheTablesOfTheAccountTest extends BrowserTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->signIn(self::user('alice'));
    }

    #[Test]
    #[DataProvider('provideThePagesOfATable')]
    public function aTableOfTheAccountIsHeldInItsFrame(string $page, string $table): void
    {
        // When
        $crawler = $this->browser->request('GET', $page);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertCount(1, $crawler->filter('div[data-table] > table[' . $table . ']'));
    }

    #[Test]
    public function everyCellOfALineIsLabelledByTheHeadingOfItsColumn(): void
    {
        // When
        $crawler = $this->browser->request('GET', '/account/sessions');

        // Then
        $headings = $crawler->filter('div[data-table] > table[data-sessions] thead th')->each(self::heading(...));
        $labels = $crawler->filter('div[data-table] > table[data-sessions] tbody tr:not([data-empty])')->each(self::labels(...));
        static::assertSame([$headings], $labels);
    }

    private static function heading(Crawler $heading): ?string
    {
        $text = trim($heading->text());

        return $text === '' ? null : $text;
    }

    /**
     * @return list<?string>
     */
    private static function labels(Crawler $line): array
    {
        return $line->filter('td')->each(static fn (Crawler $cell): ?string => $cell->attr('data-label'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideThePagesOfATable(): iterable
    {
        yield 'the acts' => ['/account/acts', 'data-acts'];
        yield 'the changes of the profile' => ['/account/profile/changes', 'data-changes'];
        yield 'the consents' => ['/account/consents', 'data-consents'];
        yield 'the notifications' => ['/account/notifications', 'data-subscriptions'];
        yield 'the passkeys' => ['/account/passkeys', 'data-passkeys'];
        yield 'the sessions' => ['/account/sessions', 'data-sessions'];
    }
}
