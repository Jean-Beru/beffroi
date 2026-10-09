<?php

declare(strict_types=1);

namespace App\Demonstration\Controller;

use App\Demonstration\AskedFlow;
use App\Demonstration\Live\FlowDriver;
use App\Demonstration\Trace\TraceStore;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * A run started over (issue #462): the trace of that flow is emptied and the client of it holds nothing
 * again. What the previous run exchanged is gone, which is the only way a flow played twice is not read
 * as one flow played oddly.
 *
 * A flow the demonstration drives is opened as the client of the lab; a flow that is replayed is simply
 * forgotten, and shows nothing until it is played again.
 */
#[AsController]
final readonly class OpenController
{
    public const string ROUTE = 'app_demonstration_open';

    public function __construct(
        private AskedFlow $asked,
        private FlowDriver $driver,
        private TraceStore $traces,
        private UrlGeneratorInterface $urls,
    ) {
    }

    #[Route('/flow/open', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $picture = $this->asked->picture($request);
        if ($picture === null) {
            throw new NotFoundHttpException('This provider serves no flow of that name.');
        }
        $client = $this->asked->client($request);
        if ($this->driver->open($picture->grantType) === null && $client !== null) {
            $this->traces->forget($picture->grantType->value, $client);
        }

        return new RedirectResponse($this->urls->generate(FlowController::ROUTE, [
            AskedFlow::PARAMETER => $picture->grantType->value,
            ...($client === null ? [] : [AskedFlow::CLIENT_PARAMETER => $client]),
        ]));
    }
}
