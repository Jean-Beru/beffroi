<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\SectorIdentifierUnavailableException;
use Beffroi\Oidc\Port\SectorIdentifierDocumentFetcherInterface;

final class FakeSectorIdentifierDocumentFetcher implements SectorIdentifierDocumentFetcherInterface
{
    /**
     * @var list<ClientUri>
     */
    public private(set) array $fetched = [];

    public ?SectorIdentifierUnavailableException $failure = null;

    /**
     * @param list<string> $redirectUris
     */
    public function __construct(
        private readonly array $redirectUris = [],
    ) {
    }

    public function fetch(ClientUri $sectorIdentifierUri): array
    {
        $this->fetched[] = $sectorIdentifierUri;
        if ($this->failure !== null) {
            throw $this->failure;
        }

        return $this->redirectUris;
    }
}
