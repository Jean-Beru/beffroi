<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use function is_string;
use Symfony\Component\HttpFoundation\Request;

/**
 * Which parameters of an HTTP request the module reads: the query of a GET or the form body of a POST
 * for a browser endpoint, the form body only for a server-to-server one (RFC 6750 §2.3, RFC 9700
 * §4.3.2). The values are handed over as PHP decoded them, arrays included; a numeric key is dropped.
 */
final readonly class RequestParameters
{
    /**
     * @return array<string, mixed>
     */
    public static function ofBrowserRequest(Request $request): array
    {
        return self::named($request->isMethod('POST') ? $request->request->all() : $request->query->all());
    }

    /**
     * @return array<string, mixed>
     */
    public static function ofForm(Request $request): array
    {
        return self::named($request->request->all());
    }

    /**
     * @param array<array-key, mixed> $parameters
     *
     * @return array<string, mixed>
     */
    private static function named(array $parameters): array
    {
        $named = [];
        foreach ($parameters as $name => $value) {
            if (is_string($name)) {
                $named[$name] = $value;
            }
        }

        return $named;
    }
}
