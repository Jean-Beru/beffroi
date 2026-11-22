<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Support;

use DateTimeImmutable;
use DateTimeZone;
use Psr\Clock\ClockInterface;
use function sprintf;

/**
 * model.md section 5.2, section 9.7
 */
final readonly class FrozenClock implements ClockInterface
{
    private DateTimeImmutable $now;

    public function __construct(DateTimeImmutable $now)
    {
        $this->now = $now->setTimezone(new DateTimeZone('UTC'));
    }

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }

    public function movedBy(int $seconds): self
    {
        return new self($this->now->modify(sprintf('%+d seconds', $seconds)));
    }
}
