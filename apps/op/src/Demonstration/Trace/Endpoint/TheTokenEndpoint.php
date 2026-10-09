<?php

declare(strict_types=1);

namespace App\Demonstration\Trace\Endpoint;

use App\Demonstration\Trace\NamedClient;
use App\Demonstration\Trace\RecordedEndpointInterface;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;
use Beffroi\Oidc\Domain\Flow\TokenEndpointHops;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use function is_string;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Where every flow ends up, whatever brought it there (RFC 6749 §3.2). The flow a call belongs to is
 * the "grant_type" it names, looked up among the wired grants: a name the provider does not serve is
 * a request it refuses, and a hop of no picture.
 */
final readonly class TheTokenEndpoint implements RecordedEndpointInterface
{
    public function recognises(Request $request, Response $response, ProviderEndpoints $endpoints): bool
    {
        return ServedAt::is($request, $endpoints->token);
    }

    public function flowOf(Request $request, ServedGrantsInterface $served): ?GrantTypeName
    {
        $asked = $request->request->get('grant_type');
        if (! is_string($asked) || $asked === '') {
            return null;
        }
        foreach ($served->servedGrantTypes() as $grantType) {
            if ($grantType->value === $asked) {
                return $grantType;
            }
        }

        return null;
    }

    public function clientOf(Request $request): ?string
    {
        return NamedClient::of($request);
    }

    public function hops(): array
    {
        return [TokenEndpointHops::REQUEST, TokenEndpointHops::RESPONSE];
    }
}
