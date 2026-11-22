<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Fixture;

use function array_key_last;
use function array_shift;
use Closure;
use function explode;
use function is_array;
use function is_string;
use LogicException;
use function parse_str;
use function sprintf;
use function strtolower;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * An HTTP client that answers what it is told to and keeps what each request carried, as a test reads it: the
 * method, the URL, the headers by their lowercase name, the form of the body and the body itself.
 *
 * @phpstan-type Request array{method: string, url: string, headers: array<string, string>, form: array<array-key, mixed>, body: string}
 */
final class RecordedRequests
{
    /**
     * @var list<Request>
     */
    public array $requests = [];

    public readonly MockHttpClient $client;

    /**
     * @param Closure(string, string, self): MockResponse $answer
     */
    private function __construct(Closure $answer)
    {
        $this->client = new MockHttpClient(function (string $method, string $url, array $options) use ($answer): MockResponse {
            $this->record($method, $url, $options);

            return $answer($method, $url, $this);
        });
    }

    /**
     * The responses given, in their order, and a 500 once they are spent.
     *
     * @param list<MockResponse> $responses
     */
    public static function answering(array $responses): self
    {
        return new self(static function () use (&$responses): MockResponse {
            return array_shift($responses) ?? new MockResponse('', ['http_code' => 500]);
        });
    }

    /**
     * What the route answers for the method and the URL of each request, knowing what was sent before it.
     *
     * @param Closure(string, string, self): MockResponse $route
     */
    public static function routed(Closure $route): self
    {
        return new self($route);
    }

    /**
     * @return Request
     */
    public function last(): array
    {
        return $this->requests[array_key_last($this->requests) ?? 0] ?? throw new LogicException('No request was sent.');
    }

    /**
     * The first request sent with the method to the URL.
     *
     * @return Request
     */
    public function to(string $method, string $url): array
    {
        foreach ($this->requests as $request) {
            if ($request['method'] === $method && $request['url'] === $url) {
                return $request;
            }
        }

        throw new LogicException(sprintf('No %s %s was sent.', $method, $url));
    }

    /**
     * A field of the form of a request, empty when it carries none.
     *
     * @param Request $request
     */
    public static function field(array $request, string $name): string
    {
        $value = $request['form'][$name] ?? '';

        return is_string($value) ? $value : '';
    }

    /**
     * @param array<array-key, mixed> $options
     */
    private function record(string $method, string $url, array $options): void
    {
        $headers = [];
        $given = $options['headers'] ?? [];
        foreach (is_array($given) ? $given : [] as $header) {
            if (is_string($header)) {
                [$name, $value] = [...explode(': ', $header, 2), ''];
                $headers[strtolower($name)] = $value;
            }
        }
        $body = is_string($options['body'] ?? null) ? $options['body'] : '';
        parse_str($body, $form);
        $this->requests[] = [
            'method' => $method,
            'url' => $url,
            'headers' => $headers,
            'form' => $form,
            'body' => $body,
        ];
    }
}
