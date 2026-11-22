<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Architecture §6, the pages: the frame is what the stylesheet scrolls, so that a table wider than the screen
 * never takes the page sideways with it.
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
