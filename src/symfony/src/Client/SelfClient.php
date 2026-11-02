<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Client;

use Beffroi\Core\Domain\Tenant\Issuer;
use function hash_equals;
use SensitiveParameter;
use function sprintf;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Routing\Exception\ExceptionInterface as RoutingException;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * The application that hosts the bundle, as a client of the provider it hosts (issue #282): it names the routes it is
 * reached at, and the URLs it registers are the paths the router writes for them under the origin of the issuer, the
 * application and the provider being served under the same host. Nothing is guessed from the request being served, as
 * nothing is for the endpoints of the provider (RouterEndpointLocator).
 *
 * What it declares is what a deployment would write for it under "clients", so the core knows it as an ordinary
 * client: its URLs, its secret, and the consent a first-party application is the named exception of. Everything else
 * is left to the defaults of a deployment (DeploymentDefaults).
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
        $origin = new Issuer($this->issuer)->origin();

        return [
            'secret' => $this->secret,
            'redirect_uris' => [$origin . $this->path('redirect_route', $this->redirectRoute)],
            'post_logout_redirect_uris' => $this->postLogoutRoute === null ? [] : [$origin . $this->path('post_logout_route', $this->postLogoutRoute)],
            'requires_consent' => false,
        ];
    }

    /**
     * @throws InvalidConfigurationException when the router writes no URL for that route
     */
    private function path(string $key, string $route): string
    {
        try {
            return $this->router->generate($route, [], UrlGeneratorInterface::ABSOLUTE_PATH);
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
        }
    }
}
