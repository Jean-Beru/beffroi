<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Symfony\Component\HttpFoundation\Response;

/**
 * A route of the application, next to the routes of the provider: answers 200 with the name of the
 * plane its route declares, so that the plane guard can be shown to leave it alone.
 */
final readonly class ProbeController
{
    public function __invoke(string $plane): Response
    {
        return new Response($plane);
    }
}
