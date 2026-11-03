<?php

declare(strict_types=1);

namespace App\Demonstration\Trace;

use App\Demonstration\ProviderEndpointsOfTheTenant;
use App\Plane\Plane;
use Beffroi\Oidc\Domain\Flow\FlowPicture;
use Beffroi\Oidc\Port\FlowPicturesInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use function http_build_query;
use function is_string;
use Psr\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\Attribute\AutowireIterator;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Throwable;

/**
 * What this provider saw of a flow (issue #462), written into the trace of the demonstration as it is
 * served. It is what makes a replay possible at all: an authorization code is a sequence of full page
 * navigations across two origins, and the call that matters most, the token request, is made from one
 * server to another and no browser is in it. A narrator living in a page cannot see either; this side
 * sees both.
 *
 * It records nothing of a call the demonstration made itself: a hop the demonstration took is recorded
 * by the demonstration, which holds the request it sent and the answer it got, and this would be the
 * same hop a second time.
 *
 * A hop the picture does not say repeats is drawn once, so a request parked and resumed is one request;
 * a hop the picture says repeats is drawn every time, which is what a client polling a token endpoint
 * does; and a trace begins again at the first hop of its picture, so a client signing in twice is two
 * runs and not one run read oddly.
 *
 * Wired in development and in the suite of the application, never in a deployment, as the endpoints the
 * conformance tools drive are: it holds what a lab exchanged with itself, tokens and all, and nothing
 * of the product reads it.
 */
final readonly class ProviderSideRecorder implements EventSubscriberInterface
{
    /**
     * What the demonstration's own calls carry, so that this recorder leaves them to it.
     */
    public const string AGENT = 'beffroi-demonstration';

    /**
     * The tag the wiring puts on every call the demonstration recognises (config/packages/demonstration.yaml).
     */
    public const string ENDPOINTS = 'app.demonstration.endpoint';

    /**
     * @param iterable<RecordedEndpointInterface> $endpoints one class per call it recognises, collected
     *                                                       by the tag the wiring puts on them
     */
    public function __construct(
        #[AutowireIterator(self::ENDPOINTS)]
        private iterable $endpoints,
        private ServedGrantsInterface $served,
        private FlowPicturesInterface $pictures,
        private ProviderEndpointsOfTheTenant $provider,
        private TraceStore $traces,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @return array<string, array{string, int}>
     */
    public static function getSubscribedEvents(): array
    {
        // after everything that writes a response: what is recorded is what left
        return [KernelEvents::RESPONSE => ['record', -1024]];
    }

    public function record(ResponseEvent $event): void
    {
        $request = $event->getRequest();
        $route = $request->attributes->get('_route');
        if (! $event->isMainRequest() || ! is_string($route) || Plane::ofRoute($route) === null) {
            return;
        }
        if ($request->headers->get('User-Agent') === self::AGENT) {
            return;
        }
        try {
            $endpoints = $this->provider->endpoints();
        } catch (Throwable) {
            // a provider that cannot say where its endpoints are has nothing to record against
            return;
        }
        // every call the demonstration recognises records what it recognises: one call can be two
        // hops of two pictures, and the answer that carries an authorization response is recognised by
        // what it is rather than by where it was served
        foreach ($this->endpoints as $recognised) {
            if ($recognised->recognises($request, $event->getResponse(), $endpoints)) {
                $this->draw($request, $event->getResponse(), $recognised);
            }
        }
    }

    private function draw(Request $request, Response $response, RecordedEndpointInterface $recognised): void
    {
        $flow = $recognised->flowOf($request, $this->served);
        if ($flow === null) {
            return;
        }
        $picture = $this->pictures->of($flow);
        if ($picture === null) {
            return;
        }
        $clientId = $recognised->clientOf($request);
        $trace = $clientId === null
            ? $this->traces->lastOf($flow->value)
            : $this->traces->of($flow->value, $clientId) ?? $this->traces->opened($flow->value, $clientId);
        if ($trace === null) {
            // a hop that names no client, of a flow nobody has played here: nothing to join
            return;
        }

        [$sent, $answered] = $recognised->hops();
        // A trace begins at the first hop of its picture: a client bringing an authorization request
        // again is a flow played again, and what the previous run exchanged is replaced rather than
        // added to. Without this a second sign-in of the same client would be drawn as the first.
        if ($sent !== null && $sent === $picture->hops[0]->name && $trace->drew($sent)) {
            $trace = $this->traces->opened($flow->value, $trace->clientId);
        }
        $at = $this->clock->now();
        $drawn = false;
        if ($sent !== null && self::draws($picture, $sent, $trace)) {
            $trace = $trace->with(TracedHop::sent(
                $sent,
                $at,
                $request->getMethod(),
                $request->getUri(),
                self::sentPayload($request),
            ));
            $drawn = true;
        }
        if ($answered !== null && self::draws($picture, $answered, $trace)) {
            $trace = $trace->with(TracedHop::answered(
                $answered,
                $at,
                $response->getStatusCode(),
                self::answeredPayload($response),
            ));
            $drawn = true;
        }
        if ($drawn) {
            $this->traces->save($trace);
        }
    }

    /**
     * The picture says whether a hop is drawn again: a polled token request is, a request parked and
     * resumed is one request and is not.
     */
    private static function draws(FlowPicture $picture, string $hop, FlowTrace $trace): bool
    {
        foreach ($picture->hops as $drawn) {
            if ($drawn->name === $hop) {
                return $drawn->repeats || ! $trace->drew($hop);
            }
        }

        return false;
    }

    /**
     * What the request carried: its body, or the fields it was parsed into when the body has already
     * been read, which is what a worker leaves behind; the query for a request that has no body.
     */
    private static function sentPayload(Request $request): string
    {
        if ($request->isMethod(Request::METHOD_GET)) {
            return $request->getQueryString() ?? '';
        }
        $body = $request->getContent();

        return $body !== '' ? $body : http_build_query($request->request->all());
    }

    /**
     * What the answer carried: its body, or, for an answer that moves the browser, the address it was
     * moved to, which is where everything an authorization response carries travels.
     */
    private static function answeredPayload(Response $response): string
    {
        $location = $response->headers->get('Location');
        if ($location !== null) {
            return $location;
        }
        $body = $response->getContent();

        return $body === false ? '' : $body;
    }
}
