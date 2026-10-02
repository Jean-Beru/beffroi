<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use function array_pad;
use function count;
use function explode;
use function is_string;
use function str_contains;
use function str_starts_with;
use Symfony\Component\HttpFoundation\Request;
use function urldecode;

/**
 * Which parameters of an HTTP request the module reads: the query of a GET or the form body of a POST
 * for a browser endpoint, the form body only for a server-to-server one (RFC 6750 §2.3, RFC 9700
 * §4.3.2). The values are handed over as PHP decoded them, arrays included; a numeric key is dropped.
 *
 * A name the request carried more than once is handed over as the list of what it carried. PHP keeps
 * the last occurrence of a repeated name and says nothing of the others, so the occurrences are counted
 * on the encoded source itself: the module then refuses the repetition where its specification forbids
 * it (RFC 6749 §3.1) and reads it where one allows it ("resource", RFC 8707 §2), instead of acting on a
 * request nobody sent.
 */
final readonly class RequestParameters
{
    /**
     * @return array<string, mixed>
     */
    public static function ofBrowserRequest(Request $request): array
    {
        return $request->isMethod('POST')
            ? self::named($request->request->all(), self::body($request))
            : self::named($request->query->all(), self::queryString($request));
    }

    /**
     * @return array<string, mixed>
     */
    public static function ofForm(Request $request): array
    {
        return self::named($request->request->all(), self::body($request));
    }

    /**
     * @param array<array-key, mixed> $parameters
     *
     * @return array<string, mixed>
     */
    private static function named(array $parameters, string $source): array
    {
        $named = [];
        foreach ($parameters as $name => $value) {
            if (is_string($name)) {
                $named[$name] = $value;
            }
        }
        foreach (self::repeated($source) as $name => $values) {
            $named[$name] = $values;
        }

        return $named;
    }

    /**
     * The names the source carries more than once, with everything they carried, in order. A name PHP
     * decodes into a structure of its own ("a[b]") is left to PHP, which is the one that knows what it
     * made of it.
     *
     * @return array<string, list<string>>
     */
    private static function repeated(string $source): array
    {
        $occurrences = [];
        foreach (explode('&', $source) as $pair) {
            if ($pair === '') {
                continue;
            }
            [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
            $name = urldecode($name);
            if ($name === '' || str_contains($name, '[')) {
                continue;
            }
            $occurrences[$name][] = urldecode($value);
        }

        $repeated = [];
        foreach ($occurrences as $name => $values) {
            if (count($values) > 1) {
                $repeated[$name] = $values;
            }
        }

        return $repeated;
    }

    private static function queryString(Request $request): string
    {
        $query = $request->server->get('QUERY_STRING');

        return is_string($query) ? $query : '';
    }

    /**
     * An encoded form and nothing else: any other body is read by whoever knows its shape, and a
     * multipart one carries no "&" to count anything on.
     */
    private static function body(Request $request): string
    {
        $contentType = $request->headers->get('Content-Type');
        if ($contentType === null || ! str_starts_with($contentType, 'application/x-www-form-urlencoded')) {
            return '';
        }
        $body = $request->getContent();

        return is_string($body) ? $body : '';
    }
}
