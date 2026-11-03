<?php

declare(strict_types=1);

namespace App\Http;

use function count;
use Beffroi\Core\Port\UuidGeneratorInterface;
use function is_string;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Uid\Uuid;

/**
 * The name a client and this provider give one exchange (FAPI 1.0 Advanced Final §6.2.1): every answer
 * of a protected resource of the provider carries `x-fapi-interaction-id`, the value the request named
 * when it named one and a UUID drawn for it when it did not, so that the client and the provider find
 * the same exchange when they read their logs side by side.
 *
 * The value belongs to the exchange and not to what the exchange asked for: the answer carries it
 * whatever the request asked and whether it is served or refused, and nothing of it is a claim of a token
 * or a condition of one.
 *
 * It is read once, where the controller that will answer is known, and written once, where the answer is
 * written: an endpoint carries the header by serving a resource (`ServesAProtectedResourceInterface`)
 * and not by writing it itself. The pages of the interaction plane carry none, no specification asking
 * it of a page a browser reaches.
 *
 * A value that is not the UUID §6.2.1 asks the client for names no exchange on either side, so it is not
 * echoed: the provider draws one, as it does for a request that named none. A request naming the header
 * twice has named it once too often and is answered the same way, unarbitrated, since which of the two
 * was read would decide what the client finds in its own logs. Neither case is a refusal, §6.2.1 naming
 * none, where RFC 9449 §4.3 names one for two DPoP proofs (`DpopProofHeader`).
 */
final readonly class FapiInteractionId
{
    public const string HEADER = 'x-fapi-interaction-id';

    /**
     * Where the name of the exchange waits between the two moments of a request that has one: the answer
     * of a resource is the only thing that reads it.
     */
    private const string ATTRIBUTE = '_beffroi_fapi_interaction_id';

    public function __construct(
        private UuidGeneratorInterface $uuids,
    ) {
    }

    #[AsEventListener(event: KernelEvents::CONTROLLER)]
    public function onKernelController(ControllerEvent $event): void
    {
        if (! $event->getController() instanceof ServesAProtectedResourceInterface) {
            return;
        }
        $request = $event->getRequest();
        $request->attributes->set(self::ATTRIBUTE, $this->ofRequest($request));
    }

    #[AsEventListener(event: KernelEvents::RESPONSE)]
    public function onKernelResponse(ResponseEvent $event): void
    {
        $interactionId = $event->getRequest()->attributes->get(self::ATTRIBUTE);
        if (! is_string($interactionId)) {
            return;
        }
        $event->getResponse()->headers->set(self::HEADER, $interactionId);
    }

    /**
     * The one value the request named, when it is the UUID a client is asked to send (§6.2.1, RFC 9562
     * §4), and a UUID drawn for it in every other case. What is drawn says nothing of when it was drawn,
     * an exchange being named and not dated by it.
     */
    private function ofRequest(Request $request): string
    {
        $named = $request->headers->all(self::HEADER);
        $one = count($named) === 1 ? $named[0] : null;

        return $one !== null && Uuid::isValid($one) ? $one : $this->uuids->opaque()->toRfc4122();
    }
}
