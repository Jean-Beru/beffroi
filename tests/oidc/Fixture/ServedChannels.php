<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Domain\EndSession\LogoutChannel;
use Beffroi\Oidc\Port\ServedLogoutChannelsInterface;

final readonly class ServedChannels implements ServedLogoutChannelsInterface
{
    /**
     * @param list<LogoutChannel> $channels
     */
    private function __construct(
        private array $channels,
    ) {
    }

    public static function both(): self
    {
        return new self([LogoutChannel::BackChannel, LogoutChannel::FrontChannel]);
    }

    public static function backChannelOnly(): self
    {
        return new self([LogoutChannel::BackChannel]);
    }

    /**
     * Front-Channel Logout 1.0 §3
     */
    public static function frontChannelOnly(): self
    {
        return new self([LogoutChannel::FrontChannel]);
    }

    public static function none(): self
    {
        return new self([]);
    }

    public function servedLogoutChannels(): array
    {
        return $this->channels;
    }
}
