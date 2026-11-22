<?php

declare(strict_types=1);

/*
 * The client of "castor demo --device": a program with no browser and no secret, using the grant of RFC 8628.
 */

use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * RFC 8628
 */
final class DeviceClient
{
    public const string GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';

    /**
     * RFC 8628 §3.5
     */
    private const int SLOW_DOWN_SECONDS = 5;

    /**
     * RFC 8628 §3.2
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
     * RFC 8628 §3.1, §3.2
     *
     * @throws RuntimeException
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
     * RFC 8628 §3.4, §3.5
     *
     * @param callable(array<string, mixed>): void $pending told of every refusal to answer yet
     *
     * @throws RuntimeException
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
 * @throws RuntimeException
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
    // Decoded only to print its RFC 9068 §2.2 claims: a client verifies nothing of a token it merely carries.
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
