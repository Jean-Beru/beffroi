<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Messenger;

use function array_shift;
use Closure;
use function count;
use function explode;
use function is_array;
use function is_string;
use LogicException;
use function parse_str;
use function sprintf;
use function strtolower;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\ResponseInterface;
use function trim;

final class LogoutEndpoints
{
    /**
     * @var list<array{url: string, headers: array<string, list<string>>, parameters: array<string, mixed>}>
     */
    public private(set) array $requests = [];

    /**
     * @param list<Closure(): ResponseInterface> $answers at least one
     */
    public function __construct(
        private array $answers,
    ) {
    }

    /**
     * @param list<Closure(): ResponseInterface> $answers one per attempt, at least one
     */
    public function willAnswer(array $answers): void
    {
        $this->answers = $answers;
        $this->requests = [];
    }

    /**
     * Back-Channel Logout 1.0 §2.8
     *
     * @return Closure(): ResponseInterface
     */
    public static function answering(int $status): Closure
    {
        return static fn (): ResponseInterface => new MockResponse('', [
            'http_code' => $status,
        ]);
    }

    /**
     * Decision 0006
     *
     * @return Closure(): ResponseInterface
     */
    public static function redirectingTo(string $location): Closure
    {
        return static fn (): ResponseInterface => new MockResponse('', [
            'http_code' => 302,
            'response_headers' => [
                'location' => $location,
            ],
        ]);
    }

    /**
     * @return Closure(): ResponseInterface
     */
    public static function timingOut(): Closure
    {
        return static fn (): ResponseInterface => throw new TransportException('Idle timeout reached for "https://slow.test/backchannel-logout".');
    }

    public function takeOver(ContainerInterface $container): void
    {
        $container->set('http_client', new MockHttpClient($this->answer(...)));
    }

    /**
     * @param array<string, mixed> $options
     */
    private function answer(string $method, string $url, array $options): ResponseInterface
    {
        if ($method !== 'POST') {
            throw new LogicException(sprintf('A logout token is posted, not sent with %s.', $method));
        }
        $this->requests[] = [
            'url' => $url,
            'headers' => self::headersOf($options),
            'parameters' => self::parametersOf($options['body'] ?? ''),
        ];
        $answer = count($this->answers) > 1 ? array_shift($this->answers) : $this->answers[0] ?? null;

        return (
            $answer === null
                ? new MockResponse('', [
                    'http_code' => 200,
                ]) : $answer()
        );
    }

    /**
     * Back-Channel Logout 1.0 §2.5
     *
     * @return array<string, mixed>
     */
    private static function parametersOf(mixed $body): array
    {
        $parsed = [];
        if (is_string($body)) {
            parse_str($body, $parsed);
        }
        $parameters = [];
        foreach ($parsed as $name => $value) {
            $parameters[(string) $name] = $value;
        }

        return $parameters;
    }

    /**
     * MockHttpClient hands the headers over as "Name: value" lines.
     *
     * @param array<string, mixed> $options
     *
     * @return array<string, list<string>>
     */
    private static function headersOf(array $options): array
    {
        $headers = [];
        foreach (is_array($options['headers'] ?? null) ? $options['headers'] : [] as $line) {
            if (! is_string($line)) {
                continue;
            }
            [$name, $value] = explode(':', $line, 2)
            + [
                1 => '',
            ];
            $headers[strtolower($name)][] = trim($value);
        }

        return $headers;
    }
}
