<?php

declare(strict_types=1);

namespace App\Push;

use function base64_decode;
use function base64_encode;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Exception\InvalidArgumentException;
use function is_string;
use function mb_str_pad;
use function mb_strlen;
use function rtrim;
use function sprintf;
use const STR_PAD_LEFT;
use function strtr;

/**
 * The application server key of a tenant in the one shape a browser takes it (RFC 8292 §3.2, Push API
 * §7.2): the uncompressed point of SEC 1 §2.3.3, sixty-five octets of "\x04" and the two coordinates, in
 * base64url. What the tenant keeps is a JWK (architecture §3.3), what a browser subscribes with is this,
 * and the conversion between the two is here and nowhere else: the page that hands the key out and the
 * sender that signs with it read the same octets, or the push service would refuse a request made for a
 * subscription that was taken out under the other reading.
 */
final readonly class ApplicationServerKey
{
    /**
     * RFC 7518 §6.2.1.2: a coordinate of P-256 is thirty-two octets, left-padded to that.
     */
    public const int COORDINATE_LENGTH = 32;

    /**
     * SEC 1 §2.3.3: what says the two coordinates follow whole.
     */
    private const string UNCOMPRESSED = "\x04";

    /**
     * @param string $kid the key of the tenant this is the public half of
     * @param string $publicKey the uncompressed point, base64url
     */
    private function __construct(
        public string $kid,
        public string $publicKey,
    ) {
    }

    /**
     * @throws InvalidArgumentException when the key is not a pair over P-256 carrying both coordinates
     */
    public static function of(TenantKey $key): self
    {
        return new self($key->kid, self::uncompressedPoint($key->publicJwk));
    }

    /**
     * @param array<string, mixed> $jwk the members of the key (RFC 7517 §4); the private ones are ignored
     *
     * @throws InvalidArgumentException
     */
    public static function uncompressedPoint(array $jwk): string
    {
        $point = self::UNCOMPRESSED;
        foreach (['x', 'y'] as $coordinate) {
            $point .= self::octetsOf($jwk, $coordinate);
        }

        return rtrim(strtr(base64_encode($point), '+/', '-_'), '=');
    }

    /**
     * @param array<string, mixed> $jwk
     *
     * @throws InvalidArgumentException
     */
    private static function octetsOf(array $jwk, string $coordinate): string
    {
        $value = $jwk[$coordinate] ?? null;
        if (! is_string($value) || $value === '') {
            throw new InvalidArgumentException(sprintf(
                'An application server key carries the "%s" coordinate of its point (RFC 7518 section 6.2.1.2).',
                $coordinate,
            ));
        }
        $octets = base64_decode(strtr($value, '-_', '+/'), true);
        if ($octets === false || mb_strlen($octets, '8bit') > self::COORDINATE_LENGTH) {
            throw new InvalidArgumentException('An application server key is a pair over P-256 (RFC 8292 section 3.2).');
        }

        return mb_str_pad($octets, self::COORDINATE_LENGTH, "\0", STR_PAD_LEFT, '8bit');
    }
}
