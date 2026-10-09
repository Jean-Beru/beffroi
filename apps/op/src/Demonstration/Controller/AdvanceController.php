<?php

declare(strict_types=1);

namespace App\Demonstration\Controller;

use App\Demonstration\AskedFlow;
use App\Demonstration\DrawnFlow;
use App\Demonstration\Live\FlowDriver;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * One hop of a live run, taken (issue #462): the demonstration makes the next call of the flow, for
 * real, and answers with the trace as it is once it has. The Next button of the page is one call to
 * this, which is what holds a flow between two hops.
 *
 * The answer carries the whole trace and not only the hop taken, because a hop a browser took while
 * the page was waiting is in it too: that is how the code typed on another screen appears in a run the
 * demonstration never stood in for the user of.
 */
#[AsController]
final readonly class AdvanceController
{
    public const string ROUTE = 'app_demonstration_advance';

    public function __construct(
        private AskedFlow $asked,
        private DrawnFlow $drawing,
        private FlowDriver $driver,
    ) {
    }

    #[Route('/flow/advance', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $picture = $this->asked->picture($request);
        if ($picture === null) {
            throw new NotFoundHttpException('This provider serves no flow of that name.');
        }
        $trace = $this->driver->advance($picture->grantType);
        if ($trace === null) {
            return new JsonResponse([
                'error' => 'The lab registered no client for this flow, so it cannot be played from a page.',
            ], Response::HTTP_CONFLICT);
        }

        return new JsonResponse($this->drawing->of($picture, $trace));
    }
}
