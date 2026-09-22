<?php

declare(strict_types=1);

namespace Heidi\Bundle\Plane;

use function sprintf;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Refuses with a 404 the routes of the plane this process does not serve (architecture §5.2), after the
 * router and before the firewall.
 */
#[AsEventListener(event: KernelEvents::REQUEST, priority: self::PRIORITY)]
final readonly class PlaneRequestListener
{
    /**
     * Below the RouterListener (32), above the firewall (8).
     */
    public const int PRIORITY = 31;

    public function __construct(
        private Plane $plane,
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        $route = $event->getRequest()
            ->attributes->getString('_route');
        if ($route === '' || $this->plane->serves($route)) {
            return;
        }

        throw new NotFoundHttpException(sprintf('The route "%s" belongs to a plane this process does not serve (HEIDI_PLANE=%s).', $route, $this->plane->value));
    }
}
