<?php

declare(strict_types=1);

namespace Beffroi\Bundle\EndSession;

use function array_values;
use Beffroi\Oidc\Domain\EndSession\LogoutChannel;
use Beffroi\Oidc\Port\ServedLogoutChannelsInterface;

/**
 * The ways of telling a client that a session ended the integration is wired with (architecture §4.9):
 * the single source the discovery document reads, so that a channel the provider announces is a channel
 * something serves (issue #98). An integration that wires neither announces neither.
 */
final readonly class LogoutChannels implements ServedLogoutChannelsInterface
{
    /**
     * @var array<string, LogoutChannel>
     */
    private array $channels;

    /**
     * @param iterable<LogoutChannelInterface> $channels
     */
    public function __construct(iterable $channels)
    {
        $byName = [];
        foreach ($channels as $channel) {
            $byName[$channel->channel()->value] = $channel->channel();
        }
        $this->channels = $byName;
    }

    public function servedLogoutChannels(): array
    {
        return array_values($this->channels);
    }
}
