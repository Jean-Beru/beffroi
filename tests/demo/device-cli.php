<?php

declare(strict_types=1);

/*
 * The CLI of "castor demo --device" (.castor/lab/demo.php, demo_device_check): a program with no browser
 * and no secret that obtains a token by the device authorization grant (RFC 8628). It is what the second
 * success criterion of spike 6 asks for, and it is a demonstration before it is a test: run by hand it
 * prints the code to read out and the address to go to, then waits.
 *
 * Two streams, for the two readers it has. The trace a human follows goes to stderr; stdout carries one
 * JSON object per step, one per line, so that the task can read the code as soon as it is drawn, confirm it
 * in a browser while this program is still polling, and assert on every step afterwards:
 *
 *   {"step":"device_authorization", "user_code", "verification_uri", "verification_uri_complete", ...}
 *   {"step":"pending", "error", "interval", "polls"}        one per refusal to answer yet
 *   {"step":"tokens", "token_type", "scope", "expires_in", "refresh_token", "sub", "aud", "polls"}
 *   {"step":"error", "error", "description"}                and exit 1
 *
 * Options: --issuer, --client-id, --scope, --cafile (the CA of the OP), --timeout. Nothing else: a client
 * of this grant registers no redirect URI and holds no secret, so there is nothing else to give it.
 */

use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * A client with no browser (RFC 8628): it asks for a code, shows it, and polls the token endpoint until
 * somebody has answered on another device. What it must not do is poll faster than it was told
 * (§3.5): the interval belongs to the provider, and "slow_down" moves it.
 */
final class DeviceClient
{
    public const string GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';

    /**
     * RFC 8628 §3.5: the provider asks for five more seconds each time it says so.
     */
    private const int SLOW_DOWN_SECONDS = 5;

    /**
     * RFC 8628 §3.2: what a provider that names no interval means.
     */
    private const int DEFAULT_INTERVAL = 5;

    private int $polls = 0;

    public function __construct(
        private readonly HttpClientInterface $http,
        private readonly string $deviceAuthorizationEndpoint,
        private readonly string $tokenEndpoint,
        private readonly string $clientId,
        private readonly string $scope,
    ) {
    }

    /**
     * RFC 8628 §3.1, §3.2: the request a client with no browser starts with, and what comes back for the
     * user to read out.
     *
     * @throws RuntimeException when the provider refuses to start the flow
     *
     * @return array<string, mixed>
     */
    public function ask(): array
    {
        $answer = $this->post($this->deviceAuthorizationEndpoint, [
            'client_id' => $this->clientId,
            'scope' => $this->scope,
        ]);
        foreach (['device_code', 'user_code', 'verification_uri', 'expires_in'] as $member) {
            if (! isset($answer[$member])) {
                throw new RuntimeException(sprintf('The device authorization response carries no "%s" (RFC 8628 section 3.2).', $member));
            }
        }

        return $answer;
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
     * RFC 8628 §3.4, §3.5: the same request again and again until somebody answers, at the interval the
     * provider named, five seconds more each time it says to slow down. Every refusal that is not
     * "authorization_pending" nor "slow_down" ends the flow: an expired code and a refusal are answers.
     *
     * @param callable(array<string, mixed>): void $pending told of every refusal to answer yet
     *
     * @throws RuntimeException when the flow ends without tokens
     *
     * @return array<string, mixed>
     */
    public function poll(string $deviceCode, int $interval, int $timeout, callable $pending): array
    {
        $interval = $interval > 0 ? $interval : self::DEFAULT_INTERVAL;
        $deadline = time() + $timeout;
        while (true) {
            ++$this->polls;
            $answer = $this->post(
                $this->tokenEndpoint,
                [
                    'grant_type' => self::GRANT_TYPE,
                    'device_code' => $deviceCode,
                    'client_id' => $this->clientId,
                ],
                false,
            );
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
                throw new RuntimeException(sprintf('Nobody answered the code within %d seconds.', $timeout));
            }
            sleep($interval);
        }
    }

    public function polls(): int
    {
        return $this->polls;
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
 * The options of the run, each one with what a development stack makes of it: nothing else is asked of the
 * command line, a client of this grant registering no redirect URI and holding no secret.
 *
 * @throws RuntimeException when an option is given without a value
 *
 * @return array<string, string>
 */
function device_cli_options(): array
{
    $defaults = [
        'issuer' => 'https://op.localhost',
        'client-id' => 'demo-appliance',
        'scope' => 'openid profile offline_access',
        'cafile' => '',
        'timeout' => '120',
    ];
    $given = getopt('', array_map(static fn (string $name): string => $name . ':', array_keys($defaults)));
    if ($given === false) {
        throw new RuntimeException('Usage: php tests/demo/device-cli.php [--issuer=URL] [--client-id=ID] [--scope="..."] [--cafile=PATH] [--timeout=SECONDS]');
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
 * One step, on the two streams it belongs to: the line the task reads, and the sentence a human reads.
 *
 * @param array<string, mixed> $step
 */
function device_cli_step(array $step, string $said): void
{
    fwrite(STDOUT, json_encode($step, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n");
    fwrite(STDERR, $said . "\n");
}

$options = device_cli_options();
$issuer = rtrim($options['issuer'], '/');
$http = HttpClient::create(
    $options['cafile'] === ''
        ? []
        : [
            'cafile' => $options['cafile'],
        ],
);
$client = new DeviceClient(
    $http,
    $issuer . '/device_authorization',
    $issuer . '/token',
    $options['client-id'],
    $options['scope'],
);

try {
    $asked = $client->ask();
    $userCode = DeviceClient::text($asked, 'user_code');
    $verificationUri = DeviceClient::text($asked, 'verification_uri');
    device_cli_step(
        [
            'step' => 'device_authorization',
            'user_code' => $userCode,
            'verification_uri' => $verificationUri,
            'verification_uri_complete' => $asked['verification_uri_complete'] ?? null,
            'expires_in' => DeviceClient::number($asked, 'expires_in'),
            'interval' => DeviceClient::number($asked, 'interval'),
        ],
        sprintf(
            "\nGo to %s on another device and type the code:\n\n    %s\n\nWaiting for it to be confirmed.",
            $verificationUri,
            $userCode,
        ),
    );

    $tokens = $client->poll(
        DeviceClient::text($asked, 'device_code'),
        DeviceClient::number($asked, 'interval'),
        (int) $options['timeout'],
        static fn (array $pending): null => device_cli_step(
            [
                'step' => 'pending',
                ...$pending,
            ],
            sprintf('  ... not answered yet (%s), asking again in %d s', DeviceClient::text($pending, 'error'), DeviceClient::number($pending, 'interval')),
        ),
    );
    $accessToken = DeviceClient::text($tokens, 'access_token');
    // RFC 9068 §2.2: what the token says of itself, read here only to print it; a client is not a resource
    // server and reads nothing of a token it merely carries
    $claims = [];
    $parts = explode('.', $accessToken);
    if (count($parts) === 3) {
        $payload = json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true, 8);
        $claims = is_array($payload) ? $payload : [];
    }
    $tokenType = DeviceClient::text($tokens, 'token_type');
    $scope = DeviceClient::text($tokens, 'scope');
    device_cli_step(
        [
            'step' => 'tokens',
            'token_type' => $tokenType,
            'scope' => $scope,
            'expires_in' => DeviceClient::number($tokens, 'expires_in'),
            'refresh_token' => isset($tokens['refresh_token']),
            'id_token' => isset($tokens['id_token']),
            'sub' => is_string($claims['sub'] ?? null) ? $claims['sub'] : null,
            'aud' => $claims['aud'] ?? null,
            'polls' => $client->polls(),
        ],
        sprintf(
            "\nSigned in. A %s access token for \"%s\", good for %d s, %s refresh token, after %d polls.",
            $tokenType,
            $scope,
            DeviceClient::number($tokens, 'expires_in'),
            isset($tokens['refresh_token']) ? 'with a' : 'without a',
            $client->polls(),
        ),
    );
} catch (RuntimeException $exception) {
    // the step is written for the task that reads these lines, then the exception ends the process: its
    // code is what the task asserts on, as it does of the other programs of tests/demo/
    device_cli_step(
        [
            'step' => 'error',
            'error' => $exception->getMessage(),
            'polls' => $client->polls(),
        ],
        "\nThe flow ended without tokens: " . $exception->getMessage(),
    );

    throw $exception;
}
