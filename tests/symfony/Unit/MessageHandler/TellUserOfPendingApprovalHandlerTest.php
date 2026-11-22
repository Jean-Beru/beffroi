<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\MessageHandler;

use App\Message\TellUserOfPendingApproval;
use App\MessageHandler\TellUserOfPendingApprovalHandler;
use App\Messenger\NotificationNotDeliveredException;
use App\Tests\Symfony\Fixture\ScriptedApprovalChannel;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Notification\ChosenChannels;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Ciba\PendingApproval;
use Beffroi\Oidc\Domain\Ciba\PendingApprovalKind;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0048, Architecture §5.6
 */
final class TellUserOfPendingApprovalHandlerTest extends TestCase
{
    private InMemoryUserRepository $users;

    private User $alice;

    protected function setUp(): void
    {
        $this->users = new InMemoryUserRepository();
        $this->alice = Fixtures::user();
        $this->users->save($this->alice);
    }

    #[Test]
    public function everyChannelTellsThePerson(): void
    {
        // Given
        $push = ScriptedApprovalChannel::reaching();
        $mail = ScriptedApprovalChannel::reaching();

        // When
        $this->handler([$push, $mail])($this->message());

        // Then
        static::assertSame([1, 1], [$push->told, $mail->told]);
    }

    #[Test]
    public function aChannelThatFailedLeavesTheNextOneToTellThePerson(): void
    {
        // Given
        $mail = ScriptedApprovalChannel::reaching();

        // When
        $this->handler([ScriptedApprovalChannel::refusing('No browser of this user was reached: the push service answered 503.'), $mail])($this->message());

        // Then
        static::assertSame(1, $mail->told);
    }

    #[Test]
    public function aPersonOneChannelReachedIsNotToldAgain(): void
    {
        // Given
        $handler = $this->handler([ScriptedApprovalChannel::reaching(), ScriptedApprovalChannel::refusing('The SMS transport did not take the message.')]);

        // When
        $handler($this->message());

        // Then
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function aPersonNoChannelReachedBringsTheLaneBack(): void
    {
        // Given
        $handler = $this->handler([
            ScriptedApprovalChannel::refusing('No browser of this user was reached: the push service answered 503.'),
            ScriptedApprovalChannel::reachingNobody(),
            ScriptedApprovalChannel::refusing('The SMS transport did not take the message.'),
        ]);

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIs('No browser of this user was reached: the push service answered 503. The SMS transport did not take the message.');

        // When
        $handler($this->message());
    }

    #[Test]
    public function aPersonNoChannelHasAWayToReachIsTheFailureOfNothing(): void
    {
        // Given
        $handler = $this->handler([ScriptedApprovalChannel::reachingNobody(), ScriptedApprovalChannel::reachingNobody()]);

        // When
        $handler($this->message());

        // Then
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function aPersonOfAnotherTenantIsToldNothing(): void
    {
        // Given
        $channel = ScriptedApprovalChannel::reaching();
        $stranger = Fixtures::user(Fixtures::tenant('globex', 'https://id.globex.example'), 'bob', 'bob-subject');
        $this->users->save($stranger);

        // When
        $this->handler([$channel])($this->message($stranger));

        // Then
        static::assertSame(0, $channel->told);
    }

    /**
     * Decision 0050
     */
    #[Test]
    public function aChannelThePersonDidNotChooseTellsThemNothing(): void
    {
        // Given
        $this->alice->chooseChannels(new ChosenChannels(null, ['pending_approval' => ['mail']]), new DateTimeImmutable('2026-09-28T09:00:00+00:00'));
        $push = ScriptedApprovalChannel::reaching('web_push');
        $mail = ScriptedApprovalChannel::reaching('mail');

        // When
        $this->handler([$push, $mail])($this->message());

        // Then
        static::assertSame([0, 1], [$push->told, $mail->told]);
    }

    /**
     * Decision 0050
     */
    #[Test]
    public function aPersonWhoChoseNoChannelIsToldByNoneAndTheLaneDoesNotComeBack(): void
    {
        // Given
        $this->alice->chooseChannels(new ChosenChannels([]), new DateTimeImmutable('2026-09-28T09:00:00+00:00'));
        $handler = $this->handler([ScriptedApprovalChannel::refusing('No browser of this user was reached: the push service answered 503.')]);

        // When
        $handler($this->message());

        // Then
        $this->expectNotToPerformAssertions();
    }

    /**
     * @param list<ScriptedApprovalChannel> $channels
     */
    private function handler(array $channels): TellUserOfPendingApprovalHandler
    {
        return new TellUserOfPendingApprovalHandler($this->users, $channels, new PendingApprovalKind());
    }

    private function message(?User $user = null): TellUserOfPendingApproval
    {
        return new TellUserOfPendingApproval(new PendingApproval(
            $this->alice->tenant,
            ($user ?? $this->alice)->id,
            'Payment terminal at the counter',
            null,
            new DateTimeImmutable('2026-09-28T09:05:00+00:00'),
            'https://id.acme.example/approvals',
        ));
    }
}
