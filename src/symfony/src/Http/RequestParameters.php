<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use function is_string;
use Symfony\Component\HttpFoundation\Request;

/**
 * Which parameters of an HTTP request the module reads. A browser endpoint (RFC 6749 §3.1, OIDC Core
 * §3.1.2.1, RP-Initiated Logout §2) reads the query of a GET and the form body of a POST, never both. A
 * server-to-server endpoint (RFC 6749 §3.2, RFC 6750 §2.2) reads the form body only: a token in the query
 * string ends up in logs and referrers, which is why RFC 6750 §2.3 exists and RFC 9700 §4.3.2 forbids it.
 * The values are handed over as PHP decoded them, arrays included, so that the module refuses a repeated
 * parameter rather than reading one of its values. A key that is not a name (a bare "?0=") is dropped:
 * no parameter of the protocol is a number.
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
