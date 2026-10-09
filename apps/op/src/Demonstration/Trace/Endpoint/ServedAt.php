<?php

declare(strict_types=1);

namespace App\Demonstration\Trace\Endpoint;

use function parse_url;
use const PHP_URL_PATH;
use Symfony\Component\HttpFoundation\Request;

/**
 * Whether this provider served that call at that endpoint of its own, compared on the path: the
 * endpoints come from the tenant and carry its issuer, and what reached PHP is a path under it. Read
 * the same way at every call the demonstration recognises, so that no two of them read it differently.
 */
final readonly class ServedAt
{
    public static function is(Request $request, string $endpoint): bool
    {
        return parse_url($endpoint, PHP_URL_PATH) === $request->getPathInfo();
    }
}
