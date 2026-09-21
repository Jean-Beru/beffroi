<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Oidc\Domain\EndSession\LogoutChannel;
use Heidi\Oidc\Port\ServedLogoutChannelsInterface;

/**
 * The ways of telling a client that a session ended an integration wired: both, as the bundle wires
 * since spike 4, one of them, or neither, as a deployment that tells nobody.
 */
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

    public static function none(): self
    {
        return new self([]);
    }

    public function servedLogoutChannels(): array
    {
        return $this->channels;
    }
}
