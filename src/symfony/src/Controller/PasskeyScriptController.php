<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use function dirname;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The one script of the bundle (architecture §5.2): what the login page and the page of the account run
 * to hand the options to the authenticator of the browser and post back what it signed. Served by the
 * bundle itself under the path of its pages, so that it needs no asset pipeline, no CDN and no change to
 * the CSP of an application that only allows its own origin; cacheable, it carries nothing of a user.
 */
#[AsController]
final readonly class PasskeyScriptController
{
    public const string ROUTE = 'heidi_interaction_passkey_script';

    public const string FILE = 'passkey.js';

    #[Route('/passkey.js', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $response = new BinaryFileResponse(
            dirname(__DIR__, 2) . '/assets/' . self::FILE,
            Response::HTTP_OK,
            [
                'Content-Type' => 'text/javascript; charset=utf-8',
            ],
            false,
        );
        $response->setAutoEtag();
        $response->setPublic();
        $response->setMaxAge(3600);
        $response->isNotModified($request);

        return $response;
    }
}
