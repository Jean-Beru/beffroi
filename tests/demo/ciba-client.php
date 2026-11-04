<?php

declare(strict_types=1);

/*
 * The client of "castor demo --ciba": a backchannel authentication in "poll" or "ping" mode (CIBA Core 1.0).
 */

use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * CIBA Core §7
 */
final class BackchannelClient
{
    /**
     * CIBA Core §7.3
     */
    public const string GRANT_TYPE = 'urn:openid:params:grant-type:ciba';

    /**
     * CIBA Core §11
     */
    private const int SLOW_DOWN_SECONDS = 5;

    /**
     * CIBA Core §7.3
     */
    private const int DEFAULT_INTERVAL = 5;

    private int $polls = 0;

    public function __construct(
        private readonly HttpClientInterface $http,
        private readonly string $backchannelAuthenticationEndpoint,
        private readonly string $tokenEndpoint,
        private readonly string $clientId,
        private readonly string $secret,
        private readonly string $scope,
    ) {
    }

    /**
     * CIBA Core §7.1, §7.3
     *
     * @throws RuntimeException
     *
     * @return array<string, mixed>
     */
    public function ask(string $loginHint, string $bindingMessage, ?string $notificationToken): array
    {
        $body = [
            'scope' => $this->scope,
            'login_hint' => $loginHint,
            'binding_message' => $bindingMessage,
        ];
        if ($notificationToken !== null) {
            $body['client_notification_token'] = $notificationToken;
        }
        $answer = $this->post($this->backchannelAuthenticationEndpoint, $body);
        foreach (['auth_req_id', 'expires_in'] as $member) {
            if (! isset($answer[$member])) {
                throw new RuntimeException(sprintf('The backchannel authentication response carries no "%s" (CIBA Core section 7.3).', $member));
            }
        }

        return $answer;
    }

    /**
     * CIBA Core §10.1, §11
     *
     * @param callable(array<string, mixed>): void $pending told of every refusal to answer yet
     *
     * @throws RuntimeException
     *
     * @return array<string, mixed>
     */
    public function poll(string $authRequestId, int $interval, int $timeout, callable $pending): array
    {
        $interval = $interval > 0 ? $interval : self::DEFAULT_INTERVAL;
        $deadline = time() + $timeout;
        while (true) {
            $answer = $this->fetch($authRequestId);
            $error = $answer['error'] ?? null;
            if ($error === null) {
                return $answer;
            }
            if (! is_string($error) || ! in_array($error, ['authorization_pending', 'slow_down'], true)) {
                throw new RuntimeException(sprintf(
                    '%s: %s',
                    is_string($error) ? $error : 'invalid_response',
                    is_string($answer['error_description'] ?? null) ? $answer['error_description'] : 'the flow ended without tokens',
                ));
            }
            if ($error === 'slow_down') {
                $interval += self::SLOW_DOWN_SECONDS;
            }
            $pending([
                'error' => $error,
                'interval' => $interval,
                'polls' => $this->polls,
            ]);
            if ((time() + $interval) > $deadline) {
                throw new RuntimeException(sprintf('Nobody answered the request within %d seconds.', $timeout));
            }
            sleep($interval);
        }
    }

    /**
     * CIBA Core §10.2, §10.3
     *
     * @throws RuntimeException
     *
     * @return array<string, mixed>
     */
    public function collect(string $authRequestId): array
    {
        $answer = $this->fetch($authRequestId);
        $error = $answer['error'] ?? null;
        if ($error !== null) {
            throw new RuntimeException(sprintf(
                '%s: %s',
                is_string($error) ? $error : 'invalid_response',
                is_string($answer['error_description'] ?? null) ? $answer['error_description'] : 'the notified request was not answered with tokens',
            ));
        }

        return $answer;
    }

    public function polls(): int
    {
        return $this->polls;
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

    /**
     * @throws RuntimeException
     *
     * @return array<string, mixed>
     */
    private function fetch(string $authRequestId): array
    {
        ++$this->polls;

        return $this->post(
            $this->tokenEndpoint,
            [
                'grant_type' => self::GRANT_TYPE,
                'auth_req_id' => $authRequestId,
            ],
            false,
        );
    }

    /**
     * @param array<string, string> $body
     *
     * @throws RuntimeException
     *
     * @return array<string, mixed>
     */
    private function post(string $url, array $body, bool $mustSucceed = true): array
    {
        try {
            $response = $this->http->request('POST', $url, [
                'auth_basic' => $this->clientId . ':' . $this->secret,
                'body' => $body,
            ]);
            $status = $response->getStatusCode();
            $decoded = json_decode($response->getContent(false), true, 8, JSON_THROW_ON_ERROR);
        } catch (HttpExceptionInterface|JsonException $exception) {
            throw new RuntimeException(sprintf('%s answered nothing this client can read: %s', $url, $exception->getMessage()), 0, $exception);
        }
        if (! is_array($decoded)) {
            throw new RuntimeException(sprintf('%s answered something that is not a JSON object.', $url));
        }
        $answer = [];
        foreach ($decoded as $member => $value) {
            $answer[(string) $member] = $value;
        }
        if ($mustSucceed && $status >= 400) {
            throw new RuntimeException(sprintf(
                '%s: %s',
                is_string($answer['error'] ?? null) ? $answer['error'] : (string) $status,
                is_string($answer['error_description'] ?? null) ? $answer['error_description'] : 'the request was refused',
            ));
        }

        return $answer;
    }
}

/**
 * CIBA Core §10.2
 *
 * Binds every address and not the loopback one: the provider, in a container, reaches the host by its gateway.
 */
final class NotificationListener
{
    /**
     * CIBA Core §10.2
     */
    private const string PARAMETER = 'auth_req_id';

    /**
     * @var resource
     */
    private $socket;

    /**
     * @throws RuntimeException
     */
    public function __construct(int $port)
    {
        $socket = @stream_socket_server('tcp://0.0.0.0:' . $port, $errorCode, $errorMessage);
        if ($socket === false) {
            throw new RuntimeException(sprintf(
                'Cannot listen on port %d for the notification of the provider: %s (%d).',
                $port,
                (string) $errorMessage,
                (int) $errorCode,
            ));
        }
        $this->socket = $socket;
    }

    /**
     * @throws RuntimeException
     *
     * @return array{auth_req_id_matches: bool, token_matches: bool, waited: float}
     */
    public function wait(string $authRequestId, string $notificationToken, int $timeout): array
    {
        $startedAt = microtime(true);
        $deadline = $startedAt + $timeout;
        while (microtime(true) < $deadline) {
            $connection = @stream_socket_accept($this->socket, 1.0);
            if ($connection === false) {
                continue;
            }
            $request = self::read($connection);
            $body = json_decode(self::bodyOf($request), true);
            $carried = is_array($body) && is_string($body[self::PARAMETER] ?? null) ? $body[self::PARAMETER] : '';
            $presented = self::bearerOf($request);
            $matches = $carried !== '' && hash_equals($authRequestId, $carried);
            $authenticated = $presented !== null && hash_equals($notificationToken, $presented);
            self::answer($connection, $matches && $authenticated ? '204 No Content' : '401 Unauthorized');
            fclose($connection);
            if (! $matches || ! $authenticated) {
                continue;
            }

            return [
                'auth_req_id_matches' => true,
                'token_matches' => true,
                'waited' => round(microtime(true) - $startedAt, 3),
            ];
        }

        throw new RuntimeException(sprintf('The provider did not call this client back within %d seconds.', $timeout));
    }

    public function close(): void
    {
        fclose($this->socket);
    }

    /**
     * @param resource $connection
     */
    private static function read($connection): string
    {
        stream_set_timeout($connection, 5);
        $request = '';
        while (! str_contains($request, "\r\n\r\n")) {
            $chunk = fgets($connection, 8192);
            if ($chunk === false) {
                return $request;
            }
            $request .= $chunk;
        }
        $length = preg_match('/^content-length:\s*(\d+)/im', $request, $matches) === 1 ? (int) $matches[1] : 0;
        $read = strlen(self::bodyOf($request));
        while ($read < $length) {
            $chunk = fread($connection, max(1, $length - $read));
            if ($chunk === false || $chunk === '') {
                break;
            }
            $request .= $chunk;
            $read += strlen($chunk);
        }

        return $request;
    }

    private static function bodyOf(string $request): string
    {
        $separator = strpos($request, "\r\n\r\n");

        return $separator === false ? '' : substr($request, $separator + 4);
    }

    /**
     * RFC 6750 §2.1
     */
    private static function bearerOf(string $request): ?string
    {
        return preg_match('/^authorization:\s*Bearer\s+(\S+)/im', $request, $matches) === 1 ? $matches[1] : null;
    }

    /**
     * @param resource $connection
     */
    private static function answer($connection, string $status): void
    {
        fwrite($connection, sprintf("HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", $status));
    }
}

/**
 * @throws RuntimeException
 *
 * @return array<string, string>
 */
function ciba_cli_options(): array
{
    $defaults = [
        'issuer' => 'https://op.localhost',
        'client-id' => 'demo-ciba-poll',
        'secret' => '',
        'mode' => 'poll',
        'login-hint' => '',
        'binding-message' => 'Invoice 4711',
        'scope' => 'openid profile',
        'notification-port' => '8004',
        'cafile' => '',
        'timeout' => '120',
    ];
    $given = getopt('', array_map(static fn (string $name): string => $name . ':', array_keys($defaults)));
    if ($given === false) {
        throw new RuntimeException('Usage: php tests/demo/ciba-client.php --secret=SECRET [--issuer=URL] [--client-id=ID] [--mode=poll|ping] [--login-hint=NAME] [--binding-message="..."] [--scope="..."] [--notification-port=PORT] [--cafile=PATH] [--timeout=SECONDS]');
    }
    $options = $defaults;
    foreach ($defaults as $name => $default) {
        $value = $given[$name] ?? null;
        if (is_string($value)) {
            $options[$name] = $value;
        }
    }
    if ($options['secret'] === '') {
        throw new RuntimeException('A client of this flow is a confidential one: pass its secret with --secret.');
    }
    // No default: what a "login_hint" names is the provider's to decide (CIBA Core §7.1, §15).
    if ($options['login-hint'] === '') {
        throw new RuntimeException('Name the user the request is made for with --login-hint, as the provider reads one.');
    }
    if (! in_array($options['mode'], ['poll', 'ping'], true)) {
        throw new RuntimeException('The mode is "poll" or "ping"; "push" is not served (CIBA Core section 4).');
    }

    return $options;
}

/**
 * @param array<string, mixed> $step
 */
function ciba_cli_step(array $step, string $said): void
{
    fwrite(STDOUT, json_encode($step, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n");
    fwrite(STDERR, $said . "\n");
}

$options = ciba_cli_options();
$issuer = rtrim($options['issuer'], '/');
$http = HttpClient::create(
    $options['cafile'] === ''
        ? []
        : [
            'cafile' => $options['cafile'],
        ],
);
$client = new BackchannelClient(
    $http,
    $issuer . '/backchannel_authentication',
    $issuer . '/token',
    $options['client-id'],
    $options['secret'],
    $options['scope'],
);
$calledBack = $options['mode'] === 'ping';
$notificationToken = $calledBack ? rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=') : null;
$listener = $calledBack ? new NotificationListener((int) $options['notification-port']) : null;

try {
    $asked = $client->ask($options['login-hint'], $options['binding-message'], $notificationToken);
    $authRequestId = BackchannelClient::text($asked, 'auth_req_id');
    ciba_cli_step(
        [
            'step' => 'backchannel_authentication',
            // An auth_req_id is a credential: a step carries enough of it to follow it, never the whole.
            'auth_req_id_prefix' => substr($authRequestId, 0, 8),
            'expires_in' => BackchannelClient::number($asked, 'expires_in'),
            'interval' => BackchannelClient::number($asked, 'interval'),
            'mode' => $options['mode'],
        ],
        sprintf(
            "\nAsked %s to approve \"%s\" on a device of their own, for %d s.\n%s",
            $options['login-hint'],
            $options['binding-message'],
            BackchannelClient::number($asked, 'expires_in'),
            $calledBack
                ? sprintf('Waiting to be called back on port %s.', $options['notification-port'])
                : sprintf('Asking again every %d s until they have.', BackchannelClient::number($asked, 'interval')),
        ),
    );

    if ($listener !== null && $notificationToken !== null) {
        $notified = $listener->wait($authRequestId, $notificationToken, (int) $options['timeout']);
        ciba_cli_step(
            [
                'step' => 'notification',
                ...$notified,
            ],
            sprintf('  ... called back after %.1f s, with the token this client gave and the request it is waiting on.', $notified['waited']),
        );
        $tokens = $client->collect($authRequestId);
    } else {
        $tokens = $client->poll(
            $authRequestId,
            BackchannelClient::number($asked, 'interval'),
            (int) $options['timeout'],
            static fn (array $pending): null => ciba_cli_step(
                [
                    'step' => 'pending',
                    ...$pending,
                ],
                sprintf(
                    '  ... not answered yet (%s), asking again in %d s',
                    BackchannelClient::text($pending, 'error'),
                    BackchannelClient::number($pending, 'interval'),
                ),
            ),
        );
    }

    $accessToken = BackchannelClient::text($tokens, 'access_token');
    // Decoded only to print its RFC 9068 §2.2 claims: a client verifies nothing of a token it merely carries.
    $claims = [];
    $parts = explode('.', $accessToken);
    if (count($parts) === 3) {
        $payload = json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true, 8);
        $claims = is_array($payload) ? $payload : [];
    }
    $tokenType = BackchannelClient::text($tokens, 'token_type');
    $scope = BackchannelClient::text($tokens, 'scope');
    ciba_cli_step(
        [
            'step' => 'tokens',
            'token_type' => $tokenType,
            'scope' => $scope,
            'expires_in' => BackchannelClient::number($tokens, 'expires_in'),
            'refresh_token' => isset($tokens['refresh_token']),
            'id_token' => isset($tokens['id_token']),
            'sub' => is_string($claims['sub'] ?? null) ? $claims['sub'] : null,
            'aud' => $claims['aud'] ?? null,
            'polls' => $client->polls(),
        ],
        sprintf(
            "\nAnswered. A %s access token for \"%s\", good for %d s, %s ID token, after %d request(s) to the token endpoint.",
            $tokenType,
            $scope,
            BackchannelClient::number($tokens, 'expires_in'),
            isset($tokens['id_token']) ? 'with an' : 'without an',
            $client->polls(),
        ),
    );
} catch (RuntimeException $exception) {
    ciba_cli_step(
        [
            'step' => 'error',
            'error' => $exception->getMessage(),
            'polls' => $client->polls(),
        ],
        "\nThe flow ended without tokens: " . $exception->getMessage(),
    );

    throw $exception;
} finally {
    $listener?->close();
}
