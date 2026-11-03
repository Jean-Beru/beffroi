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

/**
 * What the firewall of the application asks the provider is answered by the kernel that serves the provider
 * (issue #282): each request it sends is handled as a request of its own while the request of the browser waits, so
 * that the application signs in at the provider it serves with nothing between the two but HTTP. Nothing of this
 * kernel reaches a host.
 */
final readonly class RequestsToThisKernel
{
    public function __construct(
        private KernelInterface $kernel,
    ) {
    }

    /**
     * @param array<string, mixed> $options what HttpClient made of the request: its headers as lines, its body as a
     *                                      string
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
     * The headers of the request as PHP gives them to Symfony: each one under HTTP_ and its name in capitals, save the
     * two that CGI names without it.
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
