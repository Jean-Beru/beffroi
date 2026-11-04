<?php

declare(strict_types=1);

/*
 * The push service of "castor demo --push" (RFC 8030): it takes what it is sent and answers what it is told to.
 */

require __DIR__ . '/../../vendor/autoload.php';

final class LabPushService
{
    /**
     * RFC 8030 §5, §7.3
     */
    public const array ANSWERS = [
        201 => '201 Created',
        410 => '410 Gone',
        503 => '503 Service Unavailable',
    ];

    private const int READ_TIMEOUT = 5;

    /**
     * @var resource
     */
    private $socket;

    private int $pushes = 0;

    private ?float $previous = null;

    private bool $listening = true;

    /**
     * @throws RuntimeException
     */
    public function __construct(
        int $port,
        string $certificate,
        string $privateKey,
        private int $answer,
    ) {
        $socket = @stream_socket_server(
            'tcp://0.0.0.0:' . $port,
            $errorCode,
            $errorMessage,
            \STREAM_SERVER_BIND | \STREAM_SERVER_LISTEN,
            stream_context_create([
                'ssl' => [
                    'local_cert' => $certificate,
                    'local_pk' => $privateKey,
                    // Nobody who pushes presents a certificate, so there is no peer to verify.
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                ],
            ]),
        );
        if ($socket === false) {
            throw new RuntimeException(sprintf(
                'Cannot listen on port %d as a push service: %s (%d).',
                $port,
                (string) $errorMessage,
                (int) $errorCode,
            ));
        }
        $this->socket = $socket;
    }

    public function serve(): void
    {
        $stdin = \STDIN;
        stream_set_blocking($stdin, false);
        while (true) {
            $read = $this->listening ? [$this->socket, $stdin] : [$this->socket];
            $write = [];
            $except = [];
            if (@stream_select($read, $write, $except, 1) === false) {
                return;
            }
            foreach ($read as $stream) {
                if ($stream === $stdin) {
                    $this->listening = $this->told($stdin);

                    continue;
                }
                $this->take();
            }
        }
    }

    public function close(): void
    {
        fclose($this->socket);
    }

    private function take(): void
    {
        $connection = @stream_socket_accept($this->socket, 1.0);
        if ($connection === false) {
            return;
        }
        if (@stream_socket_enable_crypto($connection, true, \STREAM_CRYPTO_METHOD_TLS_SERVER) !== true) {
            fclose($connection);
            push_service_step(null, 'A connection was closed before the handshake completed.');

            return;
        }
        $request = self::read($connection);
        $answer = $this->answer;
        fwrite($connection, sprintf(
            "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            self::ANSWERS[$answer],
        ));
        fclose($connection);
        ++$this->pushes;
        $now = microtime(true);
        $head = self::headOf($request);
        [$method, $path] = self::requestLineOf($head);
        push_service_step(
            [
                'step' => 'push',
                'number' => $this->pushes,
                'answer' => $answer,
                'method' => $method,
                'path' => $path,
                'head' => $head,
                'body' => base64_encode(self::bodyOf($request)),
                'at' => round($now, 3),
                'since_previous' => $this->previous === null ? null : round($now - $this->previous, 3),
            ],
            sprintf('Push %d taken on %s, answered %s.', $this->pushes, $path, self::ANSWERS[$answer]),
        );
        $this->previous = $now;
    }

    /**
     * Reads from stdin the status the next push is answered; false once stdin is closed.
     *
     * @param resource $stdin
     */
    private function told($stdin): bool
    {
        $line = fgets($stdin);
        if ($line === false || trim($line) === '') {
            return ! feof($stdin);
        }
        $told = json_decode(trim($line), true);
        $answer = is_array($told) ? $told['answer'] ?? null : null;
        if (! is_int($answer) || ! isset(self::ANSWERS[$answer])) {
            push_service_step(null, sprintf('"%s" names no answer this service gives.', trim($line)));

            return true;
        }
        $this->answer = $answer;
        push_service_step(
            [
                'step' => 'answer',
                'answer' => $answer,
            ],
            sprintf('The next push will be answered %s.', self::ANSWERS[$answer]),
        );

        return true;
    }

    /**
     * @param resource $connection
     */
    private static function read($connection): string
    {
        stream_set_timeout($connection, self::READ_TIMEOUT);
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

    private static function headOf(string $request): string
    {
        $separator = strpos($request, "\r\n\r\n");

        return $separator === false ? $request : substr($request, 0, $separator);
    }

    private static function bodyOf(string $request): string
    {
        $separator = strpos($request, "\r\n\r\n");

        return $separator === false ? '' : substr($request, $separator + 4);
    }

    /**
     * @return array{string, string} the method and the target
     */
    private static function requestLineOf(string $head): array
    {
        return preg_match('#^(\S+)\s+(\S+)#', $head, $matches) === 1 ? [$matches[1], $matches[2]] : ['', ''];
    }
}

/**
 * @param array<string, mixed>|null $step null for a line on stderr alone
 */
function push_service_step(?array $step, string $said): void
{
    if ($step !== null) {
        fwrite(\STDOUT, json_encode($step, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES) . "\n");
    }
    fwrite(\STDERR, $said . "\n");
}

/**
 * @throws RuntimeException
 *
 * @return array{port: int, cert: string, key: string, answer: int}
 */
function push_service_options(): array
{
    $given = getopt('', ['port:', 'cert:', 'key:', 'answer:']);
    if ($given === false) {
        throw new RuntimeException('Usage: php tests/demo/push-service.php --cert=PATH --key=PATH [--port=PORT] [--answer=201|410|503]');
    }
    $port = (int) (is_string($given['port'] ?? null) ? $given['port'] : '8005');
    $certificate = is_string($given['cert'] ?? null) ? $given['cert'] : '';
    $privateKey = is_string($given['key'] ?? null) ? $given['key'] : '';
    $answer = (int) (is_string($given['answer'] ?? null) ? $given['answer'] : '201');
    foreach ([
        '--cert' => $certificate,
        '--key' => $privateKey,
    ] as $option => $path) {
        if ($path === '' || ! is_file($path)) {
            throw new RuntimeException(sprintf('%s names no file: a push service answers over HTTPS (RFC 8030 section 2).', $option));
        }
    }
    if (! isset(LabPushService::ANSWERS[$answer])) {
        throw new RuntimeException(sprintf('--answer is one of %s.', implode(', ', array_keys(LabPushService::ANSWERS))));
    }

    return [
        'port' => $port,
        'cert' => $certificate,
        'key' => $privateKey,
        'answer' => $answer,
    ];
}

try {
    $options = push_service_options();
    $service = new LabPushService($options['port'], $options['cert'], $options['key'], $options['answer']);
    push_service_step(
        [
            'step' => 'listening',
            'origin' => sprintf('https://0.0.0.0:%d', $options['port']),
            'answer' => $options['answer'],
        ],
        sprintf('A push service of the lab is listening on %d, answering %s.', $options['port'], LabPushService::ANSWERS[$options['answer']]),
    );
    $service->serve();
    $service->close();
} catch (RuntimeException $exception) {
    fwrite(\STDERR, $exception->getMessage() . "\n");

    throw $exception;
}
