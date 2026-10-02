<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Domain\EndSession\LogoutChannel;

/**
 * A list of logout channels a data provider can name, typed, because a provider hands its cases over as
 * plain arrays and a list of enumeration cases is not one PHPStan can read from there.
 */
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
