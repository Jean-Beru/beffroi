<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Push;

use App\Ciba\PendingApprovalWording;
use App\Ciba\WebPushApprovalChannel;
use App\Locale\ServedLocales;
use App\Locale\UserLocale;
use App\Tests\Symfony\Fixture\BrowsersOfAPerson;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Oidc\Domain\Ciba\BindingMessage;
use Beffroi\Oidc\Domain\Ciba\PendingApproval;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * RFC 8030, RFC 8291, RFC 8292, BCP 10027 §5.2
 */
final class WebPushApprovalChannelTest extends TestCase
{
    private BrowsersOfAPerson $browsers;

    /**
     * @var list<string>
     */
    private array $askedIn = [];

    protected function setUp(): void
    {
        $this->browsers = new BrowsersOfAPerson();
    }

    /**
     * BCP 10027 §5.2
     */
    #[Test]
    public function aBrowserIsToldWhoIsAskingAndWhereToAnswer(): void
    {
        // Given
        $this->browsers->subscribed();

        // When
        $this->channel()->tell($this->browsers->alice, $this->approval());

        // Then
        static::assertCount(1, $this->browsers->requests);
        static::assertSame(BrowsersOfAPerson::ENDPOINT, $this->browsers->requests[0]->getRequestUrl());
    }

    /**
     * Architecture §5.7, OIDC Core §5.1
     */
    #[Test]
    public function theNotificationIsWrittenInTheLanguageTheUserReads(): void
    {
        // Given
        $this->browsers->alice->updateProfile(new Profile(locale: 'fr-CA'), $this->browsers->clock->now());
        $this->browsers->subscribed();

        // When
        $this->channel()->tell($this->browsers->alice, $this->approval());

        // Then
        static::assertSame(['fr', 'fr'], $this->askedIn);
    }

    /**
     * RFC 8030 §5.2
     */
    #[Test]
    public function theMessageIsWorthDeliveringAsLongAsTheRequestIs(): void
    {
        // Given
        $this->browsers->subscribed();

        // When
        $this->channel()->tell($this->browsers->alice, $this->approval());

        // Then
        static::assertContains('TTL: 300', $this->browsers->headersOf(0));
    }

    /**
     * Decision 0048
     */
    #[Test]
    public function aPersonNoBrowserCarriesIsNotReached(): void
    {
        // When
        $reached = $this->channel()->tell($this->browsers->alice, $this->approval());

        // Then
        static::assertFalse($reached);
    }

    private function channel(): WebPushApprovalChannel
    {
        return new WebPushApprovalChannel(
            $this->browsers->broadcast(),
            new PendingApprovalWording($this->translator()),
            new UserLocale(new ServedLocales(['en', 'fr'], 'en')),
        );
    }

    private function translator(): TranslatorInterface
    {
        $translator = self::createStub(TranslatorInterface::class);
        $translator
            ->method('trans')
            ->willReturnCallback(
                function (string $id, array $parameters = [], ?string $domain = null, ?string $locale = null): string {
                    $this->askedIn[] = (string) $locale;
                    return $id;
                },
            );

        return $translator;
    }

    private function approval(): PendingApproval
    {
        return new PendingApproval(
            $this->browsers->tenant,
            $this->browsers->alice->id,
            'Payment terminal at the counter',
            new BindingMessage('Payment of 42 euros'),
            $this->browsers->clock->now()->modify('+300 seconds'),
            'https://id.acme.example/approvals',
        );
    }
}
