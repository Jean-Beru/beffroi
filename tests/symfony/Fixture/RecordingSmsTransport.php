<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use LogicException;
use Symfony\Component\Notifier\Exception\TransportException;
use Symfony\Component\Notifier\Message\MessageInterface;
use Symfony\Component\Notifier\Message\SentMessage;
use Symfony\Component\Notifier\Message\SmsMessage;
use Symfony\Component\Notifier\Transport\TransportInterface;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Keeps every text it is handed, or refuses each one the way a provider that does not answer does, naming the number
 * it was given as a provider may.
 */
final class RecordingSmsTransport implements TransportInterface
{
    public const string REFUSAL = 'Unable to send the SMS to +33600000000: the service is unavailable.';

    /**
     * @var list<SmsMessage>
     */
    public array $sent = [];

    public function __construct(
        private readonly bool $refusing = false,
    ) {
    }

    public function send(MessageInterface $message): ?SentMessage
    {
        if (! $message instanceof SmsMessage) {
            throw new LogicException('The provider texts an SmsMessage and nothing else.');
        }
        if ($this->refusing) {
            throw new TransportException(self::REFUSAL, new MockResponse('', [
                'http_code' => 503,
            ]));
        }
        $this->sent[] = $message;

        return null;
    }

    public function supports(MessageInterface $message): bool
    {
        return $message instanceof SmsMessage;
    }

    public function __toString(): string
    {
        return 'recording://sms';
    }
}
