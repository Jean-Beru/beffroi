<?php

declare(strict_types=1);

/*
 * The client of "castor demo --native": a native app answered on the loopback interface (RFC 8252 §7.3).
 */

use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * RFC 8252 §7.3
 *
 * Binds the IP literal and not a name: the registered redirect URI and the one it sends differ by the port alone.
 */
final class LoopbackListener
{
    /**
     * @var resource
     */
    private $socket;

    public readonly int $port;

    /**
     * @throws RuntimeException
     */
    public function __construct(int $port = 0)
    {
        $socket = @stream_socket_server('tcp://127.0.0.1:' . $port, $errorCode, $errorMessage);
        if ($socket === false) {
            throw new RuntimeException(sprintf('Cannot listen on 127.0.0.1:%d: %s (%d).', $port, (string) $errorMessage, (int) $errorCode));
        }
        $this->socket = $socket;
        $name = stream_socket_get_name($socket, false);
        $bound = $name === false ? '' : substr($name, (int) strrpos($name, ':') + 1);
        $this->port = (int) $bound;
    }

    public function redirectUri(string $path): string
    {
        return sprintf('http://127.0.0.1:%d%s', $this->port, $path);
    }

    /**
     * @throws RuntimeException
     *
     * @return array<string, string>
     */
    public function wait(int $timeout): array
    {
        $deadline = microtime(true) + $timeout;
        while (microtime(true) < $deadline) {
            $connection = @stream_socket_accept($this->socket, 1.0);
            if ($connection === false) {
                continue;
            }
            stream_set_timeout($connection, 5);
            $line = fgets($connection, 8192);
            if ($line === false || preg_match('#^GET\s+(\S+)\s#', $line, $matches) !== 1) {
                self::answer($connection, '400 Bad Request', 'This is the loopback listener of a native client, and that is not the redirection it waits for.');
                fclose($connection);

                continue;
            }
            self::answer($connection, '200 OK', 'Signed in. This window can be closed.');
            fclose($connection);
            $query = parse_url($matches[1], \PHP_URL_QUERY);
            $parameters = [];
            parse_str(is_string($query) ? $query : '', $parameters);
            $response = [];
            foreach ($parameters as $name => $value) {
                if (is_string($value)) {
                    $response[(string) $name] = $value;
                }
            }

            return $response;
        }

        throw new RuntimeException(sprintf('No browser came back to the loopback listener within %d seconds.', $timeout));
    }

    public function close(): void
    {
        fclose($this->socket);
    }

    /**
     * @param resource $connection
     */
    private static function answer($connection, string $status, string $said): void
    {
        $body = sprintf("<!doctype html><html lang=\"en\"><title>%s</title><p>%s</p>\n", $status, $said);
        fwrite($connection, sprintf(
            "HTTP/1.1 %s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
            $status,
            strlen($body),
            $body,
        ));
    }
}

/**
 * RFC 7636
 */
final readonly class NativeClient
{
    public function __construct(
        private HttpClientInterface $http,
        private string $authorizationEndpoint,
        private string $tokenEndpoint,
        private string $clientId,
        private string $scope,
    ) {
    }

    /**
     * RFC 6749 §4.1.1, RFC 7636 §4.3
     */
    public function authorizationUrl(string $redirectUri, string $verifier, string $state, string $nonce): string
    {
        return (
            $this->authorizationEndpoint
            . '?'
            . http_build_query([
                'response_type' => 'code',
                'client_id' => $this->clientId,
                'redirect_uri' => $redirectUri,
                'scope' => $this->scope,
                'state' => $state,
                'nonce' => $nonce,
                'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
                'code_challenge_method' => 'S256',
            ])
        );
    }

    /**
     * RFC 6749 §4.1.3, RFC 7636 §4.5
     *
     * @throws RuntimeException
     *
     * @return array<string, mixed>
     */
    public function exchange(string $code, string $redirectUri, string $verifier): array
    {
        try {
            $response = $this->http->request('POST', $this->tokenEndpoint, [
                'body' => [
                    'grant_type' => 'authorization_code',
                    'code' => $code,
                    'redirect_uri' => $redirectUri,
                    'client_id' => $this->clientId,
                    'code_verifier' => $verifier,
                ],
            ]);
            $status = $response->getStatusCode();
            $decoded = json_decode($response->getContent(false), true, 8, JSON_THROW_ON_ERROR);
        } catch (HttpExceptionInterface|JsonException $exception) {
            throw new RuntimeException(sprintf('The token endpoint answered nothing this client can read: %s', $exception->getMessage()), 0, $exception);
        }
        if (! is_array($decoded)) {
            throw new RuntimeException('The token endpoint answered something that is not a JSON object.');
        }
        $answer = [];
        foreach ($decoded as $member => $value) {
            $answer[(string) $member] = $value;
        }
        if ($status >= 400) {
            throw new RuntimeException(sprintf(
                '%s: %s',
                is_string($answer['error'] ?? null) ? $answer['error'] : (string) $status,
                is_string($answer['error_description'] ?? null) ? $answer['error_description'] : 'the code was not exchanged',
            ));
        }

        return $answer;
    }

    /**
     * @param array<string, mixed> $answer
     *
     * @throws RuntimeException
     */
    public static function text(array $answer, string $member): string
    {
        $value = $answer[$member] ?? null;

        return is_string($value) ? $value : throw new RuntimeException(sprintf('The "%s" of the answer is not a string.', $member));
    }

    /**
     * @param array<string, mixed> $answer
     */
    public static function number(array $answer, string $member, int $default = 0): int
    {
        $value = $answer[$member] ?? null;

        return is_int($value) ? $value : $default;
    }
}

/**
 * @throws RuntimeException
 *
 * @return array<string, string>
 */
function native_cli_options(): array
{
    $defaults = [
        'issuer' => 'https://op.localhost',
        'client-id' => 'demo-native',
        'scope' => 'openid profile',
        'port' => '0',
        'cafile' => '',
        'timeout' => '120',
    ];
    $given = getopt('', array_map(static fn (string $name): string => $name . ':', array_keys($defaults)));
    if ($given === false) {
        throw new RuntimeException('Usage: php tests/demo/native-cli.php [--issuer=URL] [--client-id=ID] [--scope="..."] [--port=PORT] [--cafile=PATH] [--timeout=SECONDS]');
    }
    $options = $defaults;
    foreach ($defaults as $name => $default) {
        $value = $given[$name] ?? null;
        if (is_string($value)) {
            $options[$name] = $value;
        }
    }

    return $options;
}

/**
 * @param array<string, mixed> $step
 */
function native_cli_step(array $step, string $said): void
{
    fwrite(STDOUT, json_encode($step, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n");
    fwrite(STDERR, $said . "\n");
}

const NATIVE_CALLBACK_PATH = '/callback';

$options = native_cli_options();
$issuer = rtrim($options['issuer'], '/');
$http = HttpClient::create(
    $options['cafile'] === ''
        ? []
        : [
            'cafile' => $options['cafile'],
        ],
);
$client = new NativeClient(
    $http,
    $issuer . '/authorize',
    $issuer . '/token',
    $options['client-id'],
    $options['scope'],
);
// RFC 7636 §4.1: 32 random octets give the 43 characters a verifier needs at least.
$verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
$state = bin2hex(random_bytes(16));
$nonce = bin2hex(random_bytes(16));
$listener = new LoopbackListener((int) $options['port']);

try {
    $redirectUri = $listener->redirectUri(NATIVE_CALLBACK_PATH);
    $authorizationUrl = $client->authorizationUrl($redirectUri, $verifier, $state, $nonce);
    native_cli_step(
        [
            'step' => 'listening',
            'port' => $listener->port,
            'redirect_uri' => $redirectUri,
            'authorization_url' => $authorizationUrl,
        ],
        sprintf("\nOpen this in a browser:\n\n    %s\n\nListening on %s for the answer.", $authorizationUrl, $redirectUri),
    );

    $response = $listener->wait((int) $options['timeout']);
    if (isset($response['error'])) {
        throw new RuntimeException(sprintf('%s: %s', $response['error'], $response['error_description'] ?? 'the authorization request was refused'));
    }
    // RFC 6749 §10.12, RFC 9207 §2.4: the state and the issuer are compared before the code is worth anything.
    $stateMatches = isset($response['state']) && hash_equals($state, $response['state']);
    $issuerMatches = isset($response['iss']) && hash_equals($issuer, $response['iss']);
    native_cli_step(
        [
            'step' => 'redirected',
            'state_matches' => $stateMatches,
            'iss_matches' => $issuerMatches,
            'code_present' => isset($response['code']),
        ],
        sprintf(
            '  ... the browser came back on port %d: state %s, iss %s.',
            $listener->port,
            $stateMatches ? 'matches' : 'does not match',
            $issuerMatches ? 'matches' : 'does not match',
        ),
    );
    if (! $stateMatches || ! $issuerMatches || ! isset($response['code'])) {
        throw new RuntimeException('The redirection is not the answer to the request this client made.');
    }

    $tokens = $client->exchange($response['code'], $redirectUri, $verifier);
    $accessToken = NativeClient::text($tokens, 'access_token');
    // Decoded only to print its RFC 9068 §2.2 claims: a client verifies nothing of a token it merely carries.
    $claims = [];
    $parts = explode('.', $accessToken);
    if (count($parts) === 3) {
        $payload = json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true, 8);
        $claims = is_array($payload) ? $payload : [];
    }
    $tokenType = NativeClient::text($tokens, 'token_type');
    $scope = NativeClient::text($tokens, 'scope');
    native_cli_step(
        [
            'step' => 'tokens',
            'token_type' => $tokenType,
            'scope' => $scope,
            'expires_in' => NativeClient::number($tokens, 'expires_in'),
            'id_token' => isset($tokens['id_token']),
            'sub' => is_string($claims['sub'] ?? null) ? $claims['sub'] : null,
            'aud' => $claims['aud'] ?? null,
            'port' => $listener->port,
        ],
        sprintf(
            "\nSigned in. A %s access token for \"%s\", good for %d s, on the redirection this run was given port %d for.",
            $tokenType,
            $scope,
            NativeClient::number($tokens, 'expires_in'),
            $listener->port,
        ),
    );
} catch (RuntimeException $exception) {
    native_cli_step(
        [
            'step' => 'error',
            'error' => $exception->getMessage(),
            'port' => $listener->port,
        ],
        "\nThe flow ended without tokens: " . $exception->getMessage(),
    );

    throw $exception;
} finally {
    $listener->close();
}
