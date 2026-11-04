<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Client\ClientAuthenticationRequest;
use Beffroi\Oidc\Application\Client\Method\AuthenticationMethodInterface;
use Beffroi\Oidc\Domain\Client\AssertionMethodInterface;
use Beffroi\Oidc\Domain\Client\Client;

final readonly class FakeClientAuthenticationMethod implements AssertionMethodInterface, AuthenticationMethodInterface
{
    /**
     * @param non-empty-string $name
     */
    public function __construct(
        private string $name = 'smoke_signal',
        private string $parameter = 'smoke',
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function mechanism(): string
    {
        return 'the ' . $this->parameter . ' parameter';
    }

    public function authenticatesClient(): bool
    {
        return true;
    }

    public function assertionSigningAlgorithms(): array
    {
        return ['SM256'];
    }

    public function presentedBy(ClientAuthenticationRequest $request): ?string
    {
        return $request->parameter($this->parameter) === null ? null : $request->clientId();
    }

    public function verify(ClientAuthenticationRequest $request, Client $client): void
    {
    }

    public function payRefusal(ClientAuthenticationRequest $request): void
    {
    }
}
