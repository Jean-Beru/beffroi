<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Credential;

use App\Controller\AccountController;
use App\Credential\CredentialChangeNotices;
use App\Credential\WebPushCredentialChangeChannel;
use App\Locale\Moments;
use App\Locale\ServedLocales;
use App\Locale\UserLocale;
use App\Locale\UserTimeZone;
use App\Tests\Symfony\Fixture\BrowsersOfAPerson;
use Beffroi\Core\Application\Journal\JournalRetention;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Listing\RetentionWindow;
use Beffroi\Core\Port\JournalInterface;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Routing\Generator\UrlGenerator;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * NIST SP 800-63B-4 §4.6, RFC 8030
 */
final class WebPushCredentialChangeChannelTest extends TestCase
{
    private BrowsersOfAPerson $browsers;

    protected function setUp(): void
    {
        $this->browsers = new BrowsersOfAPerson();
    }

    /**
     * NIST SP 800-63B-4 §4.6
     */
    #[Test]
    public function everyBrowserOfThePersonIsTold(): void
    {
        // Given
        $this->browsers->subscribed();
        $this->browsers->subscribed('https://push.example/f/Other');

        // When
        $this->channel(30)->tell($this->browsers->alice, $this->change());

        // Then
        static::assertSame(
            [BrowsersOfAPerson::ENDPOINT, 'https://push.example/f/Other'],
            [$this->browsers->requests[0]->getRequestUrl(), $this->browsers->requests[1]->getRequestUrl()],
        );
    }

    /**
     * RFC 8030 §5.2
     */
    #[Test]
    public function theNoticeIsWorthDeliveringAsLongAsTheJournalKeepsTheAct(): void
    {
        // Given
        $this->browsers->subscribed();

        // When
        $this->channel(30)->tell($this->browsers->alice, $this->change());

        // Then
        static::assertContains('TTL: 2592000', $this->browsers->headersOf(0));
    }

    private function channel(int $retentionDays): WebPushCredentialChangeChannel
    {
        $routes = new RouteCollection();
        $routes->add(AccountController::ROUTE, new Route('/account'));
        $translator = self::createStub(TranslatorInterface::class);
        $translator->method('trans')->willReturnArgument(0);

        return new WebPushCredentialChangeChannel(
            new CredentialChangeNotices(
                $translator,
                new UserLocale(new ServedLocales(['en', 'fr'], 'en')),
                new Moments(new UserTimeZone()),
                new UrlGenerator($routes, new RequestContext()),
            ),
            $this->browsers->broadcast(),
            new JournalRetention(self::createStub(JournalInterface::class), $this->browsers->clock, new RetentionWindow($retentionDays)),
        );
    }

    private function change(): CredentialChange
    {
        return new CredentialChange($this->browsers->alice, CredentialEnrolled::NAME, $this->browsers->clock->now(), 'passkey');
    }
}
