<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Client;

use Beffroi\Core\Domain\Tenant\Issuer;
use function hash_equals;
use function is_int;
use function is_string;
use function parse_url;
use const PHP_URL_PORT;
use const PHP_URL_SCHEME;
use SensitiveParameter;
use function sprintf;
use function strtolower;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Routing\Exception\ExceptionInterface as RoutingException;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Routing\RequestContext;

/**
 * The application that hosts the bundle, as a client of the provider it hosts (issue #282): it names the routes it is
 * reached at, and the URLs it registers are what the router writes for them in the context of the issuer, its scheme,
 * its host and its port. A route that requires neither a scheme nor a host is its path under the origin of the issuer,
 * the application and the provider being served under the same host, and a route that requires one is written as it
 * requires. Nothing is guessed from the request being served, as nothing is for the endpoints of the provider
 * (RouterEndpointLocator).
 *
 * What it declares is what a deployment would write for it under "clients", so the provider knows it as an ordinary
 * client: its URLs, its secret, and the consent a first-party application is the named exception of. Everything else
 * is what a declared client that writes nothing gets.
 *
 * Its secret is its own: the token request of the application arrives over HTTP like any other and carries it, so a
 * secret that is the secret of the kernel, which signs and seals what the application holds, is refused, whatever
 * variable carries it.
 */
final readonly class SelfClient
{
    /**
     * @throws InvalidConfigurationException when the secret is the secret of the kernel
     */
    public function __construct(
        private UrlGeneratorInterface $router,
        private string $issuer,
        private string $redirectRoute,
        private ?string $postLogoutRoute,
        #[SensitiveParameter]
        private string $secret,
        #[SensitiveParameter]
        string $kernelSecret,
    ) {
        if (hash_equals($kernelSecret, $secret)) {
            throw new InvalidConfigurationException('The "beffroi" configuration key "self_client.secret" is the secret of the kernel: the application authenticates with a secret of its own, which its token requests carry over HTTP.');
        }
    }

    /**
     * The members of RFC 7591 §2 and the secret of this client, as ClientDefinition reads a declaration.
     *
     * @throws InvalidConfigurationException when the router writes no URL for a route this client names
     *
     * @return array<string, mixed>
     */
    public function declaration(): array
    {
        $issuer = new Issuer($this->issuer);

        return [
            'secret' => $this->secret,
            'redirect_uris' => [$this->url($issuer, 'redirect_route', $this->redirectRoute)],
            'post_logout_redirect_uris' => $this->postLogoutRoute === null ? [] : [$this->url($issuer, 'post_logout_route', $this->postLogoutRoute)],
            'requires_consent' => false,
        ];
    }

    /**
     * What the router writes for that route in the context of the issuer, the base of the application kept from the
     * context the router holds, which it is given back: the router is shared with whatever else writes a URL.
     *
     * @throws InvalidConfigurationException when the router writes no URL for that route
     */
    private function url(Issuer $issuer, string $key, string $route): string
    {
        $context = $this->router->getContext();
        $this->router->setContext(self::contextOf($issuer, $context));
        try {
            return $this->router->generate($route, [], UrlGeneratorInterface::ABSOLUTE_URL);
        } catch (RoutingException $exception) {
            throw new InvalidConfigurationException(
                sprintf(
                    'The "beffroi" configuration key "self_client.%s" names "%s", a route the router writes no URL for: %s',
                    $key,
                    $route,
                    $exception->getMessage(),
                ),
                0,
                $exception,
            );
        } finally {
            $this->router->setContext($context);
        }
    }

    /**
     * The scheme, the host and the port of the issuer, which the Issuer has already held to an absolute URL.
     */
    private static function contextOf(Issuer $issuer, RequestContext $context): RequestContext
    {
        $scheme = parse_url($issuer->value, PHP_URL_SCHEME);
        $scheme = strtolower(is_string($scheme) ? $scheme : 'https');
        $port = parse_url($issuer->value, PHP_URL_PORT);

        return new RequestContext(
            $context->getBaseUrl(),
            'GET',
            $issuer->host,
            $scheme,
            $scheme === 'http' && is_int($port) ? $port : 80,
            $scheme === 'https' && is_int($port) ? $port : 443,
        );
    }
}
