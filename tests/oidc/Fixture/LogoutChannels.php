<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Domain\EndSession\LogoutChannel;

final readonly class LogoutChannels
{
    /**
     * @param list<LogoutChannel> $channels
     */
    public function __construct(
        public array $channels,
    ) {
    }
}
