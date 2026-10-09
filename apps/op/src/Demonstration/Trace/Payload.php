<?php

declare(strict_types=1);

namespace App\Demonstration\Trace;

use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use const JSON_PRETTY_PRINT;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use function parse_str;
use function parse_url;
use const PHP_URL_QUERY;
use function sprintf;
use function str_contains;
use function str_starts_with;

/**
 * A payload as the demonstration shows it (issue #462): what travelled, written out indented when it is
 * JSON so that it can be read, and the compact JWTs it carries, each under the name the payload gave it.
 *
 * The raw is never rewritten: a form a client posted is drawn as the form it posted, and an address a
 * browser was moved to is drawn as that address. What is added is a reading beside it, so that a
 * request object, a JARM response, an "at+jwt" and a DPoP proof are read as what they are.
 *
 * Which of the three shapes a payload is, is read from the payload and not from a header: a trace holds
 * what travelled, and an answer of this provider is JSON, a request to it is a form, and what a
 * redirection carries is in the query of a URL.
 */
final readonly class Payload
{
    /**
     * @param array<string, CompactJwt> $jwts by the name the payload gave them
     */
    private function __construct(
        public string $raw,
        public ?string $indented,
        public array $jwts,
    ) {
    }

    public static function of(string $raw): self
    {
        $object = json_decode($raw, true);
        if (is_array($object) && $object !== []) {
            $indented = json_encode($object, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

            return new self($raw, $indented === false ? null : $indented, self::jwtsIn($object));
        }

        return new self($raw, null, self::jwtsIn(self::query($raw) ?? ['payload' => $raw]));
    }

    /**
     * The fields of a form (RFC 6749 §4.1.3) or of the query of an address a browser was moved to
     * (§4.1.2, JARM §4.1), and null for a payload that is neither.
     *
     * @return array<array-key, mixed>|null
     */
    private static function query(string $raw): ?array
    {
        $query = str_starts_with($raw, 'http://') || str_starts_with($raw, 'https://')
            ? parse_url($raw, PHP_URL_QUERY)
            : $raw;
        if (! is_string($query) || ! str_contains($query, '=')) {
            return null;
        }
        parse_str($query, $fields);

        return $fields === [] ? null : $fields;
    }

    /**
     * Every string of a payload that reads as a compact JWT, under the name it is written at: "request",
     * "access_token", "response", and the path of a field a payload holds several levels down.
     *
     * @param array<array-key, mixed> $fields
     *
     * @return array<string, CompactJwt>
     */
    private static function jwtsIn(array $fields, string $under = ''): array
    {
        $jwts = [];
        foreach ($fields as $name => $value) {
            $path = $under === '' ? (string) $name : sprintf('%s.%s', $under, (string) $name);
            if (is_array($value)) {
                $jwts = [...$jwts, ...self::jwtsIn($value, $path)];

                continue;
            }
            if (! is_string($value)) {
                continue;
            }
            $jwt = CompactJwt::read($value);
            if ($jwt !== null) {
                $jwts[$path] = $jwt;
            }
        }

        return $jwts;
    }
}
