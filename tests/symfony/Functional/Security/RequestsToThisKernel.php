<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Security;

use function explode;
use function in_array;
use function is_array;
use function is_string;
use function parse_str;
use function str_contains;
use function str_replace;
use function strtoupper;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelInterface;
use function trim;

final readonly class RequestsToThisKernel
{
    public function __construct(
        private KernelInterface $kernel,
    ) {
    }

    /**
     * @param array<string, mixed> $options its headers as lines, its body as a string
     */
    public function __invoke(string $method, string $url, array $options): MockResponse
    {
        $body = is_string($options['body'] ?? null) ? $options['body'] : '';
        $server = self::server($options['headers'] ?? []);
        $parameters = [];
        if (str_contains($server['CONTENT_TYPE'] ?? '', 'application/x-www-form-urlencoded')) {
            parse_str($body, $parameters);
        }
        $response = $this->kernel->handle(Request::create($url, $method, $parameters, [], [], $server, $body), HttpKernelInterface::SUB_REQUEST);
        $content = $response->getContent();

        return new MockResponse(is_string($content) ? $content : '', [
            'http_code' => $response->getStatusCode(),
            'response_headers' => $response->headers->allPreserveCaseWithoutCookies(),
        ]);
    }

    /**
     * As PHP hands the headers to Symfony: under HTTP_ in capitals, save the two CGI names without it.
     *
     * @return array<string, string>
     */
    private static function server(mixed $headers): array
    {
        $server = [];
        foreach (is_array($headers) ? $headers : [] as $header) {
            if (! is_string($header) || ! str_contains($header, ':')) {
                continue;
            }
            [$name, $value] = explode(':', $header, 2);
            $key = strtoupper(str_replace('-', '_', trim($name)));
            $server[in_array($key, ['CONTENT_TYPE', 'CONTENT_LENGTH'], true) ? $key : 'HTTP_' . $key] = trim($value);
        }

        return $server;
    }
}
