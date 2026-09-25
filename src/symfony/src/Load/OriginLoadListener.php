<?php

declare(strict_types=1);

namespace Heidi\Bundle\Load;

use Heidi\Bundle\Plane\Plane;
use Heidi\Bundle\Plane\PlaneRequestListener;
use Heidi\Core\Exception\LoadBudgetSpentException;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * The load budget of the origin of a request (decision 0014), consumed on every route of the two planes
 * (architecture §5.2) once the route is named and before any of the work it asks for: before the
 * firewall opens a session or hashes anything, before an assertion is verified, a DPoP proof opened, a
 * decoy hash paid or a row written by a pushed request. A route the bundle does not serve is not
 * counted, so the routes of the host application and the endpoints of the FIDO conformance tools of a
 * development process are left alone.
 *
 * The key is the address of the client as the provider reads it behind the trusted proxies, and nothing
 * else: it is what bounds the load on the machine, which every tenant of a deployment shares, and it is
 * the only thing known about a caller that has proved nothing yet. It is not the "client_id" a request
 * carries, which a caller can choose for somebody else.
 */
#[AsEventListener(event: KernelEvents::REQUEST, priority: self::PRIORITY)]
final readonly class OriginLoadListener
{
    /**
     * Below the plane (31), which refuses the routes of the plane this process does not serve, and above
     * the firewall (8): what is counted is what the process was asked to serve.
     */
    public const int PRIORITY = PlaneRequestListener::PRIORITY - 1;

    /**
     * A request the provider reads no address of: the console driving a kernel, a request a proxy
     * stripped. Counted together rather than served free, as Symfony's own listener counts them.
     */
    public const string NO_ADDRESS = 'unknown';

    public function __construct(
        private LoadBudget $origin,
    ) {
    }

    /**
     * @throws LoadBudgetSpentException
     */
    public function __invoke(RequestEvent $event): void
    {
        // a sub-request is the request being served, not another one the provider received
        if (! $event->isMainRequest()) {
            return;
        }
        $request = $event->getRequest();
        if (Plane::ofRoute($request->attributes->getString('_route')) === null) {
            return;
        }

        $this->origin->consume($request->getClientIp() ?? self::NO_ADDRESS);
    }
}
