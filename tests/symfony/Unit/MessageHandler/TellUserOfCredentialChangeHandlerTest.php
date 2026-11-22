<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\MessageHandler;

use App\Credential\CredentialChangeChannelInterface;
use App\Message\TellUserOfCredentialChange;
use App\MessageHandler\TellUserOfCredentialChangeHandler;
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

    /**
     * @var list<array{string, string, string}>
     */
    private array $told = [];

    protected function setUp(): void
    {
        $this->users = new InMemoryUserRepository();
    }

    #[Test]
    public function everyChannelTellsThePersonOfTheChange(): void
    {
        // Given
        $alice = Fixtures::user();
        $this->users->save($alice);

        // When
        $this->handler()(new TellUserOfCredentialChange(new CredentialChange($alice, CredentialEnrolled::NAME, Fixtures::now(), 'passkey')));

        // Then
        static::assertSame(
            [
                ['first',  'alice', CredentialEnrolled::NAME],
                ['second', 'alice', CredentialEnrolled::NAME],
            ],
            $this->told,
        );
    }

    #[Test]
    public function aPersonNoLongerHeldIsToldNothing(): void
    {
        // When
        $this->handler()(new TellUserOfCredentialChange(new CredentialChange(Fixtures::user(), CredentialEnrolled::NAME, Fixtures::now(), 'passkey')));

        // Then
        static::assertSame([], $this->told);
    }

    #[Test]
    public function aPersonOfAnotherTenantIsToldNothing(): void
    {
        // Given
        $alice = Fixtures::user();
        $this->users->save($alice);
        $impostor = User::create($alice->id, Fixtures::tenant('globex', 'https://id.globex.example'), $alice->subject, 'alice', Fixtures::now());

        // When
        $this->handler()(new TellUserOfCredentialChange(new CredentialChange($impostor, CredentialEnrolled::NAME, Fixtures::now(), 'passkey')));

        // Then
        static::assertSame([], $this->told);
    }

    private function handler(): TellUserOfCredentialChangeHandler
    {
        return new TellUserOfCredentialChangeHandler($this->users, [$this->channel('first'), $this->channel('second')]);
    }

    private function channel(string $name): CredentialChangeChannelInterface
    {
        $channel = self::createStub(CredentialChangeChannelInterface::class);
        $channel
            ->method('tell')
            ->willReturnCallback(function (User $user, CredentialChange $change) use ($name): void {
                $this->told[] = [$name, $user->username, $change->act];
            });

        return $channel;
    }
}
