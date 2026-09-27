<?php

declare(strict_types=1);

/*
 * The browser of "castor demo --push" (.castor/lab/demo.php, demo_push_check): what a browser is on the
 * two sides of a web push that nothing else of this repository is. It draws the key pair and the
 * authentication secret a subscription is made of (RFC 8291 §3.1), and it opens what the push service was
 * handed, which is the one thing a mock never does.
 *
 * Nothing here needs a real browser: subscribing draws a P-256 pair and sixteen octets, which PHP draws as
 * well, and the service worker that would show the notification reads three strings this program prints.
 * What it is not is a user agent: the walk carries its HTTP, holds its session on the provider and posts
 * the form of /account/notifications with what "draw" gave it.
 *
 * One JSON object on stdin, one on stdout, as tests/demo/dpop-client.php does, so that the private half
 * never reaches a command line:
 *
 *   {"action":"draw"}
 *     -> {"p256dh", "auth", "private_key"}          the two the form takes, and the half to keep
 *
 *   {"action":"open", "private_key", "auth", "p256dh", "body", "authorization", "endpoint",
 *    "application_server_key", "subject"}
 *     -> {"payload", "title", "body", "url", "vapid": {...}}
 *
 * "open" answers what the browser would have had: the payload decrypted (RFC 8291) and what the request
 * that carried it proved (RFC 8292 §4.2). A message it cannot open, or a signature that is not of the key
 * the provider published, is an error and an exit code of 1: the walk asserts on the answer, and there is
 * no answer to give.
 */

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * The half of a subscription a browser keeps (RFC 8291 §3.1): a P-256 key pair whose public half the
 * provider encrypts to, and an authentication secret that salts the derivation, so that holding the
 * public half is not enough to write to this browser.
 */
final readonly class LabBrowser
{
    /**
     * RFC 8291 §3.1: sixteen octets.
     */
    private const int AUTH_SECRET_LENGTH = 16;

    /**
     * RFC 8291 §3.3: the length of a P-256 coordinate, and of the salt in front of a body.
     */
    private const int COORDINATE_LENGTH = 32;

    private const int SALT_LENGTH = 16;

    /**
     * RFC 8188 §2.1: the record size, which this provider writes as one record and nothing reads back.
     */
    private const int RECORD_SIZE_LENGTH = 4;

    /**
     * The uncompressed point of SEC1 §2.3.3, which is the shape both keys of a subscription travel in.
     */
    private const string UNCOMPRESSED_POINT = "\x04";

    private const int UNCOMPRESSED_POINT_LENGTH = 65;

    /**
     * RFC 8291 §3.4: what the two derivations are labelled, the second one of RFC 8188 §2.2.
     */
    private const string KEY_INFO = "WebPush: info\0";

    private const string CONTENT_ENCRYPTION_INFO = "Content-Encoding: aes128gcm\0";

    private const string NONCE_INFO = "Content-Encoding: nonce\0";

    private const int CONTENT_ENCRYPTION_KEY_LENGTH = 16;

    private const int NONCE_LENGTH = 12;

    private const int TAG_LENGTH = 16;

    /**
     * RFC 8188 §2: the delimiter of the last record, and the padding after it.
     */
    private const string LAST_RECORD = "\x02";

    /**
     * The DER of a P-256 public key, everything before the point: an EC key of prime256v1, as
     * SubjectPublicKeyInfo. What OpenSSL reads, and a point alone is not.
     */
    private const string SPKI_PREFIX = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00";

    /**
     * What a browser hands the page that subscribes it, and the half it keeps.
     *
     * @throws RuntimeException when this machine cannot draw a P-256 key
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
     * The payload as the service worker of this browser would read it (RFC 8291 §3.4, the body of
     * RFC 8188 §2): the salt, the record size, the ephemeral public key of the sender and one record.
     *
     * @throws RuntimeException when what arrived is not a message for this browser
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
     * What the request that carried the message proved (RFC 8292 §4.2): a token signed by the application
     * server key the page of the provider handed this browser, addressed to the origin of this
     * subscription, and naming somebody a push service could reach.
     *
     * @throws RuntimeException when the header proves nothing, or proves it of another key
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
            // RFC 8292 §3.2: a push service takes a request for this subscription only from the key the
            // browser subscribed under, so this is the whole of what binds the two
            'key_matches' => hash_equals($applicationServerKey, $key),
            'aud' => is_string($claims['aud'] ?? null) ? $claims['aud'] : '',
            'expected_aud' => $origin,
            'sub' => is_string($claims['sub'] ?? null) ? $claims['sub'] : '',
            'exp' => is_int($claims['exp'] ?? null) ? $claims['exp'] : 0,
            'algorithm' => is_string($algorithm) ? $algorithm : '',
        ];
    }

    /**
     * A JWK of the uncompressed point the header names, which is what verifies the signature over it.
     */
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

    /**
     * A point as OpenSSL takes a public key: the DER of an EC key of prime256v1, PEM armoured.
     */
    private static function publicKeyOf(string $point): string
    {
        return sprintf(
            "-----BEGIN PUBLIC KEY-----\n%s-----END PUBLIC KEY-----\n",
            chunk_split(base64_encode(self::SPKI_PREFIX . $point), 64, "\n"),
        );
    }

    /**
     * A coordinate OpenSSL hands back without its leading zeroes is still thirty-two octets on the wire.
     */
    private static function coordinate(string $value): string
    {
        return str_pad($value, self::COORDINATE_LENGTH, "\0", \STR_PAD_LEFT);
    }

    /**
     * What OpenSSL says went wrong, when it says anything.
     */
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
 * One value of the input, which every action of this program needs given and non-empty.
 *
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
    // the reason is written for whoever reads these lines, then the exception ends the process: its code is
    // what the walk asserts on, as it does of the other programs of tests/demo/
    fwrite(\STDERR, $exception->getMessage() . "\n");

    throw $exception;
}
