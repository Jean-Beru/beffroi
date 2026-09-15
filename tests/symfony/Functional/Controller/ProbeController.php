<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use Symfony\Component\HttpFoundation\Response;

/**
 * Stands in for the controllers to come: answers 200 with the name of the plane its route declares.
 */
final readonly class ProbeController
{
    public function __invoke(string $plane): Response
    {
        return new Response($plane);
    }
}
