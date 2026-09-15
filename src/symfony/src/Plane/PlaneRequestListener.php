<?php

declare(strict_types=1);

namespace Heidi\Bundle\Plane;

use function is_string;
use function sprintf;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Refuses, with the same 404 an unknown path gets, the routes of the plane this process does not serve
 * (architecture §5.2). Runs right after the router has named the route and before the firewall, so that a
 * protocol process never starts a session, reads a cookie or hashes anything for a request it will not
 * answer. The plane is read from the environment at runtime: the same compiled container serves the
 * three roles of architecture §6.
 */
#[AsEventListener(event: KernelEvents::REQUEST, priority: self::PRIORITY)]
final readonly class PlaneRequestListener
{
    /**
     * Just below the RouterListener (32), which sets the "_route" attribute, and above the firewall (8).
     */
    public const int PRIORITY = 31;

    public function __construct(
        private Plane $plane,
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        $route = $event->getRequest()
            ->attributes->get('_route');
        if (! is_string($route) || $this->plane->serves($route)) {
            return;
        }

        throw new NotFoundHttpException(sprintf('The route "%s" belongs to a plane this process does not serve (HEIDI_PLANE=%s).', $route, $this->plane->value));
    }
}
