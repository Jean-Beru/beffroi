<?php

declare(strict_types=1);

namespace App\Demonstration\Trace\Endpoint;

use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;
use function html_entity_decode;
use function is_string;
use function parse_url;
use const PHP_URL_HOST;
use const PHP_URL_PORT;
use const PHP_URL_SCHEME;
use function preg_match;
use function sprintf;
use function str_starts_with;
use Symfony\Component\HttpFoundation\Response;

/**
 * Whether an answer sent the browser away from this provider: a redirection to another origin, or a
 * page that posts itself to one (OIDC Response Modes §2, "form_post"). An answer that moves the browser
 * to a page of this provider, under an address of its own or a path of it, and a page of this provider
 * that asks the user something, did not.
 *
 * It is what tells the authorization response from everything else this provider answers a browser
 * while it is working on an authorization request.
 */
final readonly class AnswerThatLeaves
{
    public static function is(Response $response, ProviderEndpoints $endpoints): bool
    {
        $origin = self::origin($endpoints->authorization);
        $location = $response->headers->get('Location');
        if ($location !== null) {
            return self::absolute($location) && ! str_starts_with($location, $origin);
        }
        $body = $response->getContent();
        if (! is_string($body) || preg_match('/<form[^>]+action="([^"]+)"/i', $body, $form) !== 1) {
            return false;
        }
        $action = html_entity_decode($form[1]);

        return self::absolute($action) && ! str_starts_with($action, $origin);
    }

    private static function absolute(string $url): bool
    {
        return str_starts_with($url, 'http://') || str_starts_with($url, 'https://');
    }

    /**
     * The origin of this provider, read from an endpoint of the tenant: scheme, host and port, which is
     * what an address of its own starts with.
     */
    private static function origin(string $endpoint): string
    {
        $port = parse_url($endpoint, PHP_URL_PORT);

        return sprintf(
            '%s://%s%s',
            (string) parse_url($endpoint, PHP_URL_SCHEME),
            (string) parse_url($endpoint, PHP_URL_HOST),
            $port === null ? '' : sprintf(':%d', $port),
        );
    }
}
