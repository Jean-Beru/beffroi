<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use Heidi\Core\Domain\Session\RequestContext;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * The RequestContext of the core (architecture §3.5) for an HTTP request: when it was received, the
 * client IP the trusted proxies leave, the User-Agent header as sent. Nothing is enriched here: location
 * and device are added asynchronously, later, by whoever listens to the events.
 */
final readonly class RequestContextFactory
{
    public function __construct(
        private ClockInterface $clock,
    ) {
    }

    public function fromRequest(Request $request): RequestContext
    {
        return new RequestContext($this->clock->now(), $request->getClientIp(), $request->headers->get('User-Agent'));
    }
}
