<?php

declare(strict_types=1);

namespace App\Demonstration\Controller;

use function dirname;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The script that walks a trace on the page (issue #462): it moves the marker, reveals one hop at a
 * time, and asks for the next one. Served from here rather than from the asset pipeline, as the
 * scripts of the bundle are: the demonstration is not built with the application's stylesheet and owes
 * it nothing.
 */
#[AsController]
final readonly class FlowScriptController
{
    public const string ROUTE = 'app_demonstration_script';

    #[Route('/flow.js', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $response = new BinaryFileResponse(
            dirname(__DIR__) . '/assets/flow.js',
            Response::HTTP_OK,
            ['Content-Type' => 'text/javascript; charset=utf-8'],
            false,
        );
        $response->setAutoEtag();
        $response->isNotModified($request);

        return $response;
    }
}
