<?php

declare(strict_types=1);

/*
 * The browser of "castor demo --push": it draws a subscription (RFC 8291 §3.1) and opens the pushes it is sent.
 */

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * RFC 8291 §3.1
 */
final readonly class LabBrowser
{
    /**
     * RFC 8291 §3.1
     */
    private const int AUTH_SECRET_LENGTH = 16;

    /**
     * RFC 8291 §3.3
     */
    private const int COORDINATE_LENGTH = 32;

    private const int SALT_LENGTH = 16;

    /**
     * RFC 8188 §2.1
     */
    private const int RECORD_SIZE_LENGTH = 4;

    /**
     * SEC1 §2.3.3
     */
    private const string UNCOMPRESSED_POINT = "\x04";

    private const int UNCOMPRESSED_POINT_LENGTH = 65;

    /**
     * RFC 8291 §3.4, RFC 8188 §2.2
     */
    private const string KEY_INFO = "WebPush: info\0";

    private const string CONTENT_ENCRYPTION_INFO = "Content-Encoding: aes128gcm\0";

    private const string NONCE_INFO = "Content-Encoding: nonce\0";

    private const int CONTENT_ENCRYPTION_KEY_LENGTH = 16;

    private const int NONCE_LENGTH = 12;

    private const int TAG_LENGTH = 16;

    /**
     * RFC 8188 §2
     */
    private const string LAST_RECORD = "\x02";

    /**
     * What precedes a P-256 point in a SubjectPublicKeyInfo: OpenSSL reads no point alone.
     */
    private const string SPKI_PREFIX = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00";

    /**
     * @throws RuntimeException
     *
     * @return array{p256dh: string, auth: string, private_key: string}
     */
    public static function draw(): array
    {
        $key = openssl_pkey_new([
            'private_key_type' => \OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        if ($key === false || ! openssl_pkey_export($key, $privateKey) || ! is_string($privateKey)) {
            throw new RuntimeException(sprintf('Cannot draw a P-256 key: %s', self::opensslError()));
        }
        $details = openssl_pkey_get_details($key);
        $curve = is_array($details) && is_array($details['ec'] ?? null) ? $details['ec'] : [];
        $x = is_string($curve['x'] ?? null) ? $curve['x'] : '';
        $y = is_string($curve['y'] ?? null) ? $curve['y'] : '';

        return [
            'p256dh' => self::base64UrlEncode(self::UNCOMPRESSED_POINT . self::coordinate($x) . self::coordinate($y)),
            'auth' => self::base64UrlEncode(random_bytes(self::AUTH_SECRET_LENGTH)),
            'private_key' => $privateKey,
        ];
    }

    /**
     * RFC 8291 §3.4, RFC 8188 §2
     *
     * @throws RuntimeException
     */
    public static function open(string $body, string $privateKey, string $authSecret, string $publicKey): string
    {
        $expected = self::SALT_LENGTH + self::RECORD_SIZE_LENGTH + 1 + self::UNCOMPRESSED_POINT_LENGTH + self::TAG_LENGTH;
        if (strlen($body) <= $expected) {
            throw new RuntimeException(sprintf('The body is %d octets, too short to be an "aes128gcm" record (RFC 8188 section 2).', strlen($body)));
        }
        $salt = substr($body, 0, self::SALT_LENGTH);
        $keyIdLength = ord($body[self::SALT_LENGTH + self::RECORD_SIZE_LENGTH]);
        if ($keyIdLength !== self::UNCOMPRESSED_POINT_LENGTH) {
            throw new RuntimeException(sprintf(
                'The key identifier is %d octets; a web push carries the uncompressed point of the sender (RFC 8291 section 4).',
                $keyIdLength,
            ));
        }
        $offset = self::SALT_LENGTH + self::RECORD_SIZE_LENGTH + 1;
        $senderPublicKey = substr($body, $offset, $keyIdLength);
        $record = substr($body, $offset + $keyIdLength);
        $ciphertext = substr($record, 0, -self::TAG_LENGTH);
        $tag = substr($record, -self::TAG_LENGTH);

        $private = openssl_pkey_get_private($privateKey);
        if ($private === false) {
            throw new RuntimeException('The private half of this subscription is not a key OpenSSL reads.');
        }
        $shared = openssl_pkey_derive(self::publicKeyOf($senderPublicKey), $private, self::COORDINATE_LENGTH);
        if ($shared === false) {
            throw new RuntimeException(sprintf('The two keys agree on nothing: %s', self::opensslError()));
        }
        $ikm = hash_hkdf(
            'sha256',
            $shared,
            self::COORDINATE_LENGTH,
            self::KEY_INFO . self::base64UrlDecode($publicKey) . $senderPublicKey,
            self::base64UrlDecode($authSecret),
        );
        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-128-gcm',
            hash_hkdf('sha256', $ikm, self::CONTENT_ENCRYPTION_KEY_LENGTH, self::CONTENT_ENCRYPTION_INFO, $salt),
            \OPENSSL_RAW_DATA,
            hash_hkdf('sha256', $ikm, self::NONCE_LENGTH, self::NONCE_INFO, $salt),
            $tag,
        );
        if ($plaintext === false) {
            throw new RuntimeException('The record does not decrypt with the keys of this subscription (RFC 8291 section 3.4).');
        }
        $unpadded = rtrim($plaintext, "\0");
        if (! str_ends_with($unpadded, self::LAST_RECORD)) {
            throw new RuntimeException('The record carries no delimiter of a last record (RFC 8188 section 2).');
        }

        return substr($unpadded, 0, -1);
    }

    /**
     * RFC 8292 §4.2
     *
     * @throws RuntimeException
     *
     * @return array{key_matches: bool, aud: string, expected_aud: string, sub: string, exp: int, algorithm: string}
     */
    public static function vapid(string $header, string $endpoint, string $applicationServerKey): array
    {
        if (preg_match('/^vapid\s+t=([^,\s]+),\s*k=(\S+)$/i', trim($header), $matches) !== 1) {
            throw new RuntimeException(sprintf('"%s" is not the "vapid" scheme of RFC 8292 section 3.1.', $header));
        }
        [, $token, $key] = $matches;
        $jws = new CompactSerializer()->unserialize($token);
        $verified = new JWSVerifier(new AlgorithmManager([new ES256()]))->verifyWithKey($jws, self::jwkOf($key), 0);
        if (! $verified) {
            throw new RuntimeException('The token of the "Authorization" header is not signed by the key it names (RFC 8292 section 4.2).');
        }
        $claims = json_decode((string) $jws->getPayload(), true, 8, \JSON_THROW_ON_ERROR);
        if (! is_array($claims)) {
            throw new RuntimeException('The token of the "Authorization" header carries no claims.');
        }
        $algorithm = $jws->getSignature(0)->getProtectedHeaderParameter('alg');
        $port = parse_url($endpoint, \PHP_URL_PORT);
        $origin = sprintf(
            '%s://%s%s',
            (string) parse_url($endpoint, \PHP_URL_SCHEME),
            (string) parse_url($endpoint, \PHP_URL_HOST),
            is_int($port) ? ':' . $port : '',
        );

        return [
            'key_matches' => hash_equals($applicationServerKey, $key),
            'aud' => is_string($claims['aud'] ?? null) ? $claims['aud'] : '',
            'expected_aud' => $origin,
            'sub' => is_string($claims['sub'] ?? null) ? $claims['sub'] : '',
            'exp' => is_int($claims['exp'] ?? null) ? $claims['exp'] : 0,
            'algorithm' => is_string($algorithm) ? $algorithm : '',
        ];
    }

    private static function jwkOf(string $point): JWK
    {
        $decoded = self::base64UrlDecode($point);
        if (strlen($decoded) !== self::UNCOMPRESSED_POINT_LENGTH || ! str_starts_with($decoded, self::UNCOMPRESSED_POINT)) {
            throw new RuntimeException('The "k" of the header is not the uncompressed point of a P-256 key (RFC 8292 section 3.2).');
        }

        return new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => self::base64UrlEncode(substr($decoded, 1, self::COORDINATE_LENGTH)),
            'y' => self::base64UrlEncode(substr($decoded, 1 + self::COORDINATE_LENGTH)),
        ]);
    }

    private static function publicKeyOf(string $point): string
    {
        return sprintf(
            "-----BEGIN PUBLIC KEY-----\n%s-----END PUBLIC KEY-----\n",
            chunk_split(base64_encode(self::SPKI_PREFIX . $point), 64, "\n"),
        );
    }

    private static function coordinate(string $value): string
    {
        return str_pad($value, self::COORDINATE_LENGTH, "\0", \STR_PAD_LEFT);
    }

    private static function opensslError(): string
    {
        $reason = openssl_error_string();

        return $reason === false ? 'no reason given by OpenSSL' : $reason;
    }

    private static function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $value): string
    {
        return (string) base64_decode(strtr($value, '-_', '+/'), true);
    }
}

/**
 * @throws JsonException
 *
 * @return array<mixed>
 */
function push_browser_input(): array
{
    $input = json_decode((string) file_get_contents('php://stdin'), true, 16, \JSON_THROW_ON_ERROR);

    return is_array($input) ? $input : [];
}

/**
 * @param array<mixed> $input
 *
 * @throws RuntimeException
 */
function push_browser_string(array $input, string $name): string
{
    if (! is_string($input[$name] ?? null) || $input[$name] === '') {
        throw new RuntimeException(sprintf('"%s" is required on the input of this program.', $name));
    }

    return $input[$name];
}

try {
    $input = push_browser_input();
    $action = is_string($input['action'] ?? null) ? $input['action'] : '';
    $answer = match ($action) {
        'draw' => LabBrowser::draw(),
        'open' => (static function (array $input): array {
            $payload = LabBrowser::open(
                (string) base64_decode(push_browser_string($input, 'body'), true),
                push_browser_string($input, 'private_key'),
                push_browser_string($input, 'auth'),
                push_browser_string($input, 'p256dh'),
            );
            $shown = json_decode($payload, true, 8, \JSON_THROW_ON_ERROR);

            return [
                'payload' => $payload,
                'title' => is_array($shown) && is_string($shown['title'] ?? null) ? $shown['title'] : '',
                'body' => is_array($shown) && is_string($shown['body'] ?? null) ? $shown['body'] : '',
                'url' => is_array($shown) && is_string($shown['url'] ?? null) ? $shown['url'] : '',
                'members' => is_array($shown) ? array_keys($shown) : [],
                'vapid' => LabBrowser::vapid(
                    push_browser_string($input, 'authorization'),
                    push_browser_string($input, 'endpoint'),
                    push_browser_string($input, 'application_server_key'),
                ),
            ];
        })($input),
        default => throw new RuntimeException('The action is "draw" or "open".'),
    };
    fwrite(\STDOUT, json_encode($answer, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES) . "\n");
} catch (JsonException|RuntimeException $exception) {
    fwrite(\STDERR, $exception->getMessage() . "\n");

    throw $exception;
}
