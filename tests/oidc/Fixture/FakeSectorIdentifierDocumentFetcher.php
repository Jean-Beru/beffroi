<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\SectorIdentifierUnavailableException;
use Beffroi\Oidc\Port\SectorIdentifierDocumentFetcherInterface;

/**
 * A "sector_identifier_uri" that answers the redirection URIs the test told it to, and counts the reads.
 * Never leaves the test suite.
 */
final class FakeSectorIdentifierDocumentFetcher implements SectorIdentifierDocumentFetcherInterface
{
    /**
     * @var list<ClientUri> the URIs read, in order
     */
    public private(set) array $fetched = [];

    public ?SectorIdentifierUnavailableException $failure = null;

    /**
     * @param list<string> $redirectUris what the document lists
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
