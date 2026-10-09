<?php

declare(strict_types=1);

namespace App\Demonstration\Controller;

use App\Demonstration\AskedFlow;
use App\Demonstration\DrawnFlow;
use App\Demonstration\Live\FlowDriver;
use App\Demonstration\Trace\TraceStore;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Environment;

/**
 * One flow, drawn with what it exchanged (issue #462): the actors, the hops of the picture, and the
 * trace of the client that played it.
 *
 * Which client that is, is the one asked for, and the one that played the flow last otherwise: five
 * rungs of a ladder are five clients of one flow, each replayed on its own. A flow the demonstration
 * drives itself is played hop by hop from here; a flow that opens in a browser navigating away is
 * replayed from what this provider recorded while it happened.
 */
#[AsController]
final readonly class FlowController
{
    public const string ROUTE = 'app_demonstration_flow';

    public function __construct(
        private AskedFlow $asked,
        private DrawnFlow $drawing,
        private FlowDriver $driver,
        private TraceStore $traces,
        private Environment $twig,
    ) {
    }

    #[Route('/flow', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $picture = $this->asked->picture($request);
        if ($picture === null) {
            throw new NotFoundHttpException('This provider serves no flow of that name.');
        }
        $client = $this->asked->client($request);
        $trace = $client === null
            ? $this->traces->lastOf($picture->grantType->value)
            : $this->traces->of($picture->grantType->value, $client);

        return new Response($this->twig->render('demonstration/flow.html.twig', [
            'picture' => $picture,
            'drawing' => $this->drawing->of($picture, $trace),
            'driven' => $this->driver->drives($picture->grantType),
            'clients' => $this->traces->clientsOf($picture->grantType->value),
        ]));
    }
}
