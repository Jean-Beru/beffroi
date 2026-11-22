<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Credential;

use App\Credential\CredentialChangeChannelInterface;
use App\Credential\CredentialChangeChannels;
use App\Credential\QueuedCredentialChangeNotifier;
use App\Message\TellUserOfCredentialChange;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * NIST SP 800-63B-4 §4.6, Architecture §5.6
 */
final class QueuedCredentialChangeNotifierTest extends TestCase
{
    /**
     * @var list<object>
     */
    private array $dispatched = [];

    #[Test]
    public function eachChannelIsHandedANoticeOfItsOwn(): void
    {
        // Given
        $change = new CredentialChange(Fixtures::user(), CredentialEnrolled::NAME, Fixtures::now(), 'passkey');

        // When
        $this->notifier(['web_push', 'mail', 'sms'])->tell($change);

        // Then
        static::assertEquals(
            [
                new TellUserOfCredentialChange($change, 'web_push'),
                new TellUserOfCredentialChange($change, 'mail'),
                new TellUserOfCredentialChange($change, 'sms'),
            ],
            $this->dispatched,
        );
    }

    #[Test]
    public function aDeploymentWithoutChannelsQueuesNothing(): void
    {
        // When
        $this->notifier([])->tell(new CredentialChange(Fixtures::user(), CredentialEnrolled::NAME, Fixtures::now(), 'passkey'));

        // Then
        static::assertSame([], $this->dispatched);
    }

    /**
     * @param list<string> $names
     */
    private function notifier(array $names): QueuedCredentialChangeNotifier
    {
        $bus = self::createStub(MessageBusInterface::class);
        $bus->method('dispatch')->willReturnCallback(function (object $message): Envelope {
            $this->dispatched[] = $message;

            return new Envelope($message);
        });
        $channels = [];
        foreach ($names as $name) {
            $channel = self::createStub(CredentialChangeChannelInterface::class);
            $channel->method('name')->willReturn($name);
            $channels[] = $channel;
        }

        return new QueuedCredentialChangeNotifier($bus, new CredentialChangeChannels($channels));
    }
}
