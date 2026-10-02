<?php

declare(strict_types=1);

/*
 * The client of "castor demo --ciba" (.castor/lab/demo.php, demo_ciba_check): a program that asks for a
 * user it names and waits, with no browser of its own anywhere in the flow (CIBA Core 1.0). It is a
 * demonstration before it is a test: run by hand it prints who it asked for and the message that user will
 * read, then waits for them to answer somewhere else.
 *
 * Both delivery modes, because they are two different clients (§4). In "poll" mode it asks the token
 * endpoint again and again at the interval it was given. In "ping" mode it is called back first, so it
 * binds a listener of its own before it asks for anything, presents a token it drew to the provider, and
 * asks the token endpoint once, when it is told there is something to come and get. A token is never
 * carried to the listener: §10.3 is not served, and what the notification says is that the answer is
 * ready.
 *
 * Two streams, for the two readers it has. The trace a human follows goes to stderr; stdout carries one
 * JSON object per step, one per line, so that the task can assert on each step while this program is still
 * waiting for the next:
 *
 *   {"step":"backchannel_authentication", "auth_req_id_prefix", "expires_in", "interval", "mode"}
 *   {"step":"pending", "error", "interval", "polls"}            one per refusal to answer yet, poll mode
 *   {"step":"notification", "auth_req_id_matches", "token_matches", "waited"}       ping mode
 *   {"step":"tokens", "token_type", "scope", "expires_in", "refresh_token", "id_token", "sub", "aud", "polls"}
 *   {"step":"error", "error", "polls"}                          and exit 1
 *
 * Options: --issuer, --client-id, --secret, --mode, --login-hint (required: what a "login_hint" names is the
 * provider's to decide, and this stack reads the subject it issued), --binding-message, --scope,
 * --notification-port, --cafile (the CA of the OP), --timeout.
 */

use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * A client that asks for somebody else's approval (CIBA Core §7): it names the user, writes the message
 * that user will read on the device where they answer, and is handed an identifier for the request. What
 * it must not do is poll faster than it was told (§11): the interval belongs to the provider, and
 * "slow_down" moves it.
 */
final class BackchannelClient
{
    /**
     * CIBA Core §7.3, registered in the IANA "OAuth URI" registry.
     */
    public const string GRANT_TYPE = 'urn:openid:params:grant-type:ciba';

    /**
     * CIBA Core §11: the provider asks for five more seconds each time it says so.
     */
    private const int SLOW_DOWN_SECONDS = 5;

    /**
     * CIBA Core §7.3: what a provider that names no interval means.
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
     * CIBA Core §7.1, §7.3: the request naming the user it is made for, and what comes back for the client
     * to wait on. The notification token is the credential this provider will present back to the listener
     * of a client it calls, and a client that only polls sends none (§7.1).
     *
     * @throws RuntimeException when the provider refuses to start the flow
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
     * CIBA Core §10.1, §11: the same request again and again until the user has answered, at the interval
     * the provider named, five seconds more each time it says to slow down. Every refusal that is not
     * "authorization_pending" nor "slow_down" ends the flow: an expired request and a refusal are answers.
     *
     * @param callable(array<string, mixed>): void $pending told of every refusal to answer yet
     *
     * @throws RuntimeException when the flow ends without tokens
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
     * CIBA Core §10.2, §10.3: what a client that was called back does, which is what a poller does once. The
     * notification says the answer is ready and carries none, so this is still the token endpoint and still
     * the same grant; a request refused here is the flow ending, there being nothing left to wait for.
     *
     * @throws RuntimeException when the flow ends without tokens
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
     * A member of an answer, as the thing it must be; the provider writes them and this program reads them,
     * so a member that is not what it must be is an answer this client cannot use.
     *
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
     * One request to the token endpoint for the identifier it holds, counted, whatever comes back.
     *
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
                // CIBA Core §7.1: a client of this flow is a confidential one and authenticates at the
                // backchannel endpoint exactly as it does at the token endpoint
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
        // a JSON object decodes with keys of its own, which are the names of its members
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
 * The listener of a client the provider calls back (CIBA Core §10.2): the one endpoint of this program,
 * bound before anything is asked for, answering the one POST that says the request has been answered.
 *
 * It is what the client registered as its notification endpoint, so it verifies what it registered for:
 * the token it drew and handed to the provider, compared in constant time, and the identifier of the
 * request it is waiting on. Anything else is a caller this client did not ask for, answered 401 and
 * waited past. Nothing of a token is expected in the body, §10.3 not being served.
 *
 * It binds every address of the machine and not the loopback one: the provider runs in a container of the
 * development stack and reaches the host by its gateway, which is not 127.0.0.1 from in there.
 */
final class NotificationListener
{
    /**
     * CIBA Core §10.2: the one member of the body.
     */
    private const string PARAMETER = 'auth_req_id';

    /**
     * @var resource
     */
    private $socket;

    /**
     * @throws RuntimeException when the port is not one this program may listen on
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
     * Waits for the notification of one request, and says what it was: whether the identifier it carried is
     * the one this client is waiting on, and whether the token it was presented is the one this client drew.
     * Both are answered rather than asserted here, the walk being what judges them.
     *
     * @throws RuntimeException when nothing arrives in time
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
                // somebody this client never handed anything to, or a request it is not waiting on: the
                // answer above said so, and this listener goes back to waiting for the one it asked for
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
     * The request, headers and body, read until the body announced by "Content-Length" is in: a POST of
     * "application/json" is what this endpoint is called with, and nothing else is served here.
     *
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
     * RFC 6750 §2.1: the token the provider presents back, as it was handed to it.
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
 * The options of the run, each one with what a development stack makes of it.
 *
 * @throws RuntimeException when an option is given without a value
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
    // CIBA Core §7.1, §15: what a "login_hint" names is the provider's to decide and not this client's to
    // guess, so there is no default; this development stack reads it as the subject it issued
    // (beffroi.backchannel_authentication.login_hint).
    if ($options['login-hint'] === '') {
        throw new RuntimeException('Name the user the request is made for with --login-hint, as the provider reads one.');
    }
    if (! in_array($options['mode'], ['poll', 'ping'], true)) {
        throw new RuntimeException('The mode is "poll" or "ping"; "push" is not served (CIBA Core section 4).');
    }

    return $options;
}

/**
 * One step, on the two streams it belongs to: the line the task reads, and the sentence a human reads.
 *
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
// the credential the provider will present back to the listener below (CIBA Core §7.1): drawn here,
// never guessed, and compared in constant time when it comes back
$notificationToken = $calledBack ? rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=') : null;
$listener = $calledBack ? new NotificationListener((int) $options['notification-port']) : null;

try {
    $asked = $client->ask($options['login-hint'], $options['binding-message'], $notificationToken);
    $authRequestId = BackchannelClient::text($asked, 'auth_req_id');
    ciba_cli_step(
        [
            'step' => 'backchannel_authentication',
            // an auth_req_id is a credential of this flow: what a step carries is enough to follow it and
            // never the whole of it
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
    // RFC 9068 §2.2: what the token says of itself, read here only to print it; a client is not a resource
    // server and reads nothing of a token it merely carries
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
    // the step is written for the task that reads these lines, then the exception ends the process: its
    // code is what the task asserts on, as it does of the other programs of tests/demo/
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
