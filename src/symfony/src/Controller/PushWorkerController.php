<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\BundleScript;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The service worker that receives a push for a browser of a user (Push API §5, architecture §5.6).
 *
 * It is served at the root of the pages of the bundle and not beside the page that registers it: a
 * service worker controls the paths under the one it was served from (Service Workers §3.1.1), and the
 * page it opens when a notification is tapped is a page of this provider elsewhere under that root.
 */
#[AsController]
final readonly class PushWorkerController
{
    public const string ROUTE = 'beffroi_interaction_push_worker';

    public const string FILE = 'push-worker.js';

    public function __construct(
        private BundleScript $scripts,
    ) {
    }

    #[Route('/push-worker.js', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        return $this->scripts->serve($request, self::FILE);
    }
}
