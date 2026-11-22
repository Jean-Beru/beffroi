<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Ciba;

use App\Ciba\PendingApprovalWording;
use App\Ciba\SmsApprovalChannel;
use App\Locale\ServedLocales;
use App\Locale\UserLocale;
use App\Sms\SmsSender;
use App\Tests\Symfony\Fixture\RecordingSmsTransport;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Ciba\BindingMessage;
use Beffroi\Oidc\Domain\Ciba\PendingApproval;
use DateTimeImmutable;
use function implode;
use function is_string;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Decision 0048, CIBA Core §7.1, Architecture §5.6
 */
final class SmsApprovalChannelTest extends TestCase
{
    private RecordingSmsTransport $transport;

    private User $alice;

    protected function setUp(): void
    {
        $this->transport = new RecordingSmsTransport();
        $this->alice = Fixtures::user();
        $this->alice->changePhoneNumber('+33600000000', true, Fixtures::now());
    }

    #[Test]
    public function theTextSaysWhichProviderAsksWhoAsksAndWhereTheAnswerIsGiven(): void
    {
        // When
        $this->channel()->tell($this->alice, $this->approval());

        // Then
        static::assertSame(
            "approval.notice.title Acme\napproval.notice.body_with_message Payment terminal at the counter Payment of 42 euros\nhttps://id.acme.example/approvals",
            $this->transport->sent[0]->getSubject(),
        );
    }

    /**
     * Architecture §5.7, OIDC Core §5.1
     */
    #[Test]
    public function theTextIsWrittenInTheLanguageThePersonReads(): void
    {
        // Given
        $this->alice->updateProfile(new Profile(locale: 'fr-CA'), Fixtures::now());
        $locales = [];

        // When
        $this->channel($locales)->tell($this->alice, $this->approval());

        // Then
        static::assertSame(['fr', 'fr'], $locales);
    }

    #[Test]
    public function aPersonTextedIsReached(): void
    {
        // When
        $reached = $this->channel()->tell($this->alice, $this->approval());

        // Then
        static::assertTrue($reached);
    }

    #[Test]
    public function aPersonWithNoVerifiedNumberIsNotReached(): void
    {
        // Given
        $this->alice->changePhoneNumber('+33600000000', false, Fixtures::now());

        // When
        $reached = $this->channel()->tell($this->alice, $this->approval());

        // Then
        static::assertFalse($reached);
    }

    /**
     * @param list<string> $locales
     */
    private function channel(array &$locales = []): SmsApprovalChannel
    {
        $translator = self::createStub(TranslatorInterface::class);
        $translator
            ->method('trans')
            ->willReturnCallback(
                static function (string $id, array $parameters = [], ?string $domain = null, ?string $locale = null) use (&$locales): string {
                    $locales[] = (string) $locale;
                    $words = [$id];
                    foreach ($parameters as $value) {
                        $words[] = is_string($value) ? $value : '';
                    }

                    return implode(' ', $words);
                },
            );

        return new SmsApprovalChannel(
            new SmsSender($this->transport),
            new PendingApprovalWording($translator),
            new UserLocale(new ServedLocales(['en', 'fr'], 'en')),
        );
    }

    private function approval(): PendingApproval
    {
        return new PendingApproval(
            $this->alice->tenant,
            $this->alice->id,
            'Payment terminal at the counter',
            new BindingMessage('Payment of 42 euros'),
            new DateTimeImmutable('2026-09-28T09:05:00+00:00'),
            'https://id.acme.example/approvals',
        );
    }
}
