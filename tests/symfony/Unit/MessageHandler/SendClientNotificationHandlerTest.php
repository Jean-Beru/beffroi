<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\MessageHandler;

use App\Http\Timeout;
use App\Http\ClientNotificationSender;
use App\Message\SendClientNotification;
use App\MessageHandler\SendClientNotificationHandler;
use App\Messenger\NotificationNotDeliveredException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * CIBA Core §10.2, architecture §5.6: what the provider does with the word it owes a client that asked to
 * be called back, when that client does not take it.
 */
final class SendClientNotificationHandlerTest extends TestCase
{
    /**
     * A client that could not be reached may be reached in a minute: the lane brings the notification
     * back, on its policy and not beyond it, as it does for a logout token.
     */
    #[Test]
    public function aClientThatCannotBeReachedIsCalledAgainOnThePolicyOfTheLane(): void
    {
        // Given
        $handler = new SendClientNotificationHandler(new ClientNotificationSender(new MockHttpClient(new MockResponse('', [
            'http_code' => 503,
        ])), new Timeout(3.0)));

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIs('the client answered 503');

        // When
        $handler(new SendClientNotification(
            Fixtures::tenant(),
            'ciba-demo',
            'https://demo.test/ciba/notification',
            'the-notification-token-of-the-client',
            'the-identifier-of-the-request',
            Fixtures::context(),
        ));
    }
}
