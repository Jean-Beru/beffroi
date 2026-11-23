<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Push;

use App\Http\Timeout;
use App\Push\PushMessage;
use App\Push\WebPushSender;
use App\Tests\Symfony\Fixture\BrowsersOfAPerson;
use Beffroi\Core\Port\ApplicationServerKeyProviderInterface;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpClient\MockHttpClient;
use function sprintf;

/**
 * RFC 8292 §2.1
 */
final class WebPushSenderTest extends TestCase
{
    #[Test]
    public function itIsNotBuiltWithAnEmptySubject(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "web_push.subject" names the "mailto:" or "https:" URI a push service can reach the operator at (RFC 8292 section 2.1), and it is empty.');

        // When
        new WebPushSender(static::createStub(ApplicationServerKeyProviderInterface::class), new MockHttpClient(), new MockClock(), '', new Timeout(1.0));
    }

    /**
     * RFC 8030 §5
     */
    #[Test]
    public function aPushServiceThatCannotBeReachedIsToldOfWithoutTheEndpoint(): void
    {
        // Given
        $browsers = new BrowsersOfAPerson()->unreachable(sprintf('Could not connect to server for "%s".', BrowsersOfAPerson::ENDPOINT));
        $subscription = $browsers->subscribed();

        // When
        $delivery = $browsers->sender()->send($subscription, self::message($browsers));

        // Then
        static::assertStringStartsWith(
            'the push service cannot be reached: Failed to send notification to the endpoint: Could not connect to server for "the endpoint".',
            $delivery->detail,
        );
        static::assertStringNotContainsString(BrowsersOfAPerson::ENDPOINT, $delivery->detail);
    }

    private static function message(BrowsersOfAPerson $browsers): PushMessage
    {
        return new PushMessage('Acme', 'Something happened.', 'https://id.acme.example/account', $browsers->clock->now()->modify('+300 seconds'));
    }
}
