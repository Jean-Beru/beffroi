<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use LogicException;
use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mailer\Exception\TransportException;
use Symfony\Component\Mailer\SentMessage;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\RawMessage;

/**
 * Keeps every mail it is handed, or refuses each one the way a server that cannot be reached does, naming the
 * address it was given as a server may.
 */
final class RecordingMailTransport implements TransportInterface
{
    public const string REFUSAL = 'Expected response code "250/251/252" but got code "450", with message "450 4.2.0 <alice@acme.example>: Recipient address rejected: try again later".';

    /**
     * @var list<Email>
     */
    public array $sent = [];

    public function __construct(
        private readonly bool $refusing = false,
    ) {
    }

    public function send(RawMessage $message, ?Envelope $envelope = null): ?SentMessage
    {
        if (! $message instanceof Email) {
            throw new LogicException('The provider writes an Email and nothing else.');
        }
        if ($this->refusing) {
            throw new TransportException(self::REFUSAL, 450);
        }
        $this->sent[] = $message;

        return null;
    }

    public function __toString(): string
    {
        return 'recording://mail';
    }
}
