<?php

declare(strict_types=1);

namespace App\Demonstration\Live;

use function array_keys;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use function is_string;

/**
 * Which client the demonstration plays each flow as (issue #462), configured by the application that
 * runs the lab. A flow no client of the lab is registered for is a flow the demonstration cannot play
 * live, and the page says so rather than pretending.
 */
final readonly class DemonstrationClients
{
    /**
     * @param array<string, array{client_id: string, secret?: string|null, scope: string, login_hint?: string|null, resource?: string|null}> $clients by grant type
     */
    public function __construct(
        private array $clients,
    ) {
    }

    public function of(GrantTypeName $grantType): ?DemonstrationClient
    {
        $client = $this->clients[$grantType->value] ?? null;
        if ($client === null) {
            return null;
        }
        $secret = $client['secret'] ?? null;
        $hint = $client['login_hint'] ?? null;
        $resource = $client['resource'] ?? null;

        return new DemonstrationClient(
            $client['client_id'],
            is_string($secret) && $secret !== '' ? $secret : null,
            $client['scope'],
            is_string($hint) && $hint !== '' ? $hint : null,
            is_string($resource) && $resource !== '' ? $resource : null,
        );
    }

    /**
     * @return list<string> the grant types the lab holds a client for
     */
    public function playable(): array
    {
        return array_keys($this->clients);
    }
}
