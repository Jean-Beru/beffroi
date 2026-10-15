<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Saml\Domain\ServiceProvider\MetadataLocation;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Port\MetadataFetcherInterface;

/**
 * The document each location of the test answers, changed by the test between two refreshes; a location it was given
 * nothing for cannot be read.
 */
final class FixedMetadataFetcher implements MetadataFetcherInterface
{
    /**
     * @var array<string, string>
     */
    private array $documents = [];

    public function answer(string $location, string $document): void
    {
        $this->documents[$location] = $document;
    }

    public function fetch(MetadataLocation $location): string
    {
        return $this->documents[$location->value] ?? throw new MetadataRefusedException('The location answers nothing.');
    }
}
