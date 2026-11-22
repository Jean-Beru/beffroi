<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\MessageHandler;

use App\Credential\CredentialChangeChannelInterface;
use App\Credential\CredentialChangeChannels;
use App\Message\TellUserOfCredentialChange;
use App\MessageHandler\TellUserOfCredentialChangeHandler;
use App\Messenger\NotificationNotDeliveredException;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * NIST SP 800-63B-4 §4.6
 */
final class TellUserOfCredentialChangeHandlerTest extends TestCase
{
    private InMemoryUserRepository $users;

    private User $alice;

    /**
     * @var list<array{string, string, string}>
     */
    private array $told = [];

    protected function setUp(): void
    {
        $this->users = new InMemoryUserRepository();
        $this->alice = Fixtures::user();
        $this->users->save($this->alice);
    }

    #[Test]
    public function theChannelTheNoticeNamesTellsThePersonOfTheChange(): void
    {
        // When
        $this->handler()(new TellUserOfCredentialChange($this->change($this->alice), 'second'));

        // Then
        static::assertSame([['second', 'alice', CredentialEnrolled::NAME]], $this->told);
    }

    #[Test]
    public function aChannelTheDeploymentNoLongerWiresTellsNothing(): void
    {
        // When
        $this->handler()(new TellUserOfCredentialChange($this->change($this->alice), 'gone'));

        // Then
        static::assertSame([], $this->told);
    }

    #[Test]
    public function aPersonNoLongerHeldIsToldNothing(): void
    {
        // When
        $this->handler()(new TellUserOfCredentialChange($this->change(Fixtures::user()), 'first'));

        // Then
        static::assertSame([], $this->told);
    }

    #[Test]
    public function aPersonOfAnotherTenantIsToldNothing(): void
    {
        // Given
        $impostor = User::create($this->alice->id, Fixtures::tenant('globex', 'https://id.globex.example'), $this->alice->subject, 'alice', Fixtures::now());

        // When
        $this->handler()(new TellUserOfCredentialChange($this->change($impostor), 'first'));

        // Then
        static::assertSame([], $this->told);
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function aChannelThatDidNotReachThePersonBringsTheNoticeBack(): void
    {
        // Given
        $handler = new TellUserOfCredentialChangeHandler($this->users, new CredentialChangeChannels([$this->refusing('first')]));

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIs('The mail transport did not take the message.');

        // When
        $handler(new TellUserOfCredentialChange($this->change($this->alice), 'first'));
    }

    private function handler(): TellUserOfCredentialChangeHandler
    {
        return new TellUserOfCredentialChangeHandler($this->users, new CredentialChangeChannels([$this->channel('first'), $this->channel('second')]));
    }

    private function change(User $user): CredentialChange
    {
        return new CredentialChange($user, CredentialEnrolled::NAME, Fixtures::now(), 'passkey');
    }

    private function channel(string $name): CredentialChangeChannelInterface
    {
        $channel = self::createStub(CredentialChangeChannelInterface::class);
        $channel->method('name')->willReturn($name);
        $channel
            ->method('tell')
            ->willReturnCallback(function (User $user, CredentialChange $change) use ($name): void {
                $this->told[] = [$name, $user->username, $change->act];
            });

        return $channel;
    }

    private function refusing(string $name): CredentialChangeChannelInterface
    {
        $channel = self::createStub(CredentialChangeChannelInterface::class);
        $channel->method('name')->willReturn($name);
        $channel->method('tell')->willThrowException(new NotificationNotDeliveredException('The mail transport did not take the message.'));

        return $channel;
    }
}
