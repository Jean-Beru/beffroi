<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Symfony\Component\HttpFoundation\Response;

final readonly class ProbeController
{
    public function __invoke(string $plane): Response
    {
        return new Response($plane);
    }
}
