<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler;

use Heidi\Bundle\Http\DpopProofHeader;
use Heidi\Bundle\Http\Tls\ClientCertificateResolverInterface;
use Heidi\Bundle\Http\Tls\ForgedClientCertificateException;
use Heidi\Bundle\Plane\Plane;
use Heidi\Oidc\Exception\InvalidDpopProofException;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function str_starts_with;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Which endpoint of the provider the request reached, and what the connection brought with it: the
 * certificate the edge handed over (RFC 8705 §2, docs/mtls-at-the-edge.md) and whether a DPoP proof was
 * presented (RFC 9449 §4.1). Neither the certificate nor the proof is written down; what the panel shows
 * of a certificate is the thumbprint a token would be bound to, and of a proof, that there was one.
 *
 * A route that is none of the provider's is left alone, which is what makes the toolbar of a host
 * application show an entry on the pages of the provider and on no other.
 */
#[AsEventListener(event: KernelEvents::REQUEST, priority: self::PRIORITY)]
final readonly class OpEndpointListener
{
    /**
     * Just below the listener of the planes (architecture §5.2), so that a route this process refuses to
     * serve is never reported as one it served.
     */
    public const int PRIORITY = 30;

    public function __construct(
        private OpProfile $profile,
        private ClientCertificateResolverInterface $certificates,
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        $request = $event->getRequest();
        $route = $request->attributes->getString('_route');
        if (! $event->isMainRequest() || ! self::isAnEndpointOfTheProvider($route)) {
            return;
        }
        $this->profile->touch();
        $this->profile->record(new Observation('Request', 'Endpoint', [
            'route' => $route,
            'method' => $request->getMethod(),
            'path' => $request->getPathInfo(),
            'client certificate' => $this->certificate($request),
            'DPoP proof' => self::proof($request),
        ]));
    }

    private static function isAnEndpointOfTheProvider(string $route): bool
    {
        return str_starts_with($route, Plane::INTERACTION_ROUTE_PREFIX) || str_starts_with($route, Plane::PROTOCOL_ROUTE_PREFIX);
    }

    /**
     * What a token bound to this certificate would carry (RFC 8705 §3.1), which is all a panel needs;
     * a request the edge handed something unreadable for is said to be so, and refusing it is the
     * endpoint's business and not this one's.
     */
    private function certificate(Request $request): string
    {
        try {
            $certificate = $this->certificates->ofRequest($request);
        } catch (ForgedClientCertificateException) {
            return 'carried in a header, refused';
        } catch (InvalidArgumentException) {
            return 'handed over by the edge, and unreadable';
        }

        return $certificate === null ? 'none' : 'x5t#S256 ' . $certificate->x5tS256();
    }

    private static function proof(Request $request): string
    {
        try {
            return DpopProofHeader::ofRequest($request) === null ? 'none' : 'presented';
        } catch (InvalidDpopProofException) {
            return 'more than one, refused';
        }
    }
}
