<?php

declare(strict_types=1);

namespace App\Demonstration\Trace;

use function base64_decode;
use function count;
use function explode;
use function is_array;
use function json_decode;
use function json_encode;
use const JSON_PRETTY_PRINT;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use function strtr;

/**
 * A compact JWT as the demonstration shows it (issue #462): the token as it travelled, its header, and
 * its claims when they are there to be read. A request object, a JARM response, an "at+jwt" and a DPoP
 * proof read as what they are rather than as a blob.
 *
 * Nothing is verified here and nothing is decrypted. A JWS is three parts and its payload is readable
 * (RFC 7515 §3.1), a JWE is five and its payload is not (RFC 7516 §3.1): the second shows its header,
 * which is where the algorithms and the key are named, and says that the rest is for its recipient.
 */
final readonly class CompactJwt
{
    private function __construct(
        public string $raw,
        public string $header,
        public ?string $claims,
    ) {
    }

    /**
     * The value read as a compact JWT, null for anything that is not one. A header that is not an
     * object of JSON is not a JWT, which is what tells a token apart from any other dotted string.
     */
    public static function read(string $value): ?self
    {
        $parts = explode('.', $value);
        if (count($parts) !== 3 && count($parts) !== 5) {
            return null;
        }
        $header = self::object($parts[0]);
        if ($header === null) {
            return null;
        }
        $claims = count($parts) === 3 ? self::object($parts[1]) : null;

        return new self($value, $header, $claims);
    }

    public function encrypted(): bool
    {
        return $this->claims === null;
    }

    /**
     * One part of a compact serialization, decoded and written out again indented, or null when it is
     * not an object of JSON.
     */
    private static function object(string $part): ?string
    {
        // base64url without padding, which is what a compact serialization uses (RFC 7515 §2),
        // decoded strictly: anything outside the alphabet is not a part of a JWT at all
        $decoded = base64_decode(strtr($part, '-_', '+/'), true);
        if ($decoded === false || $decoded === '') {
            return null;
        }
        $object = json_decode($decoded, true);
        if (! is_array($object) || $object === []) {
            return null;
        }
        $written = json_encode($object, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return $written === false ? null : $written;
    }
}
