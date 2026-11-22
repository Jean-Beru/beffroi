<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Port;

use Beffroi\Saml\Port\MetadataFetcherInterface;
use Beffroi\Xml\Core\Limits;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 7
 */
final class MetadataFetcherInterfaceTest extends TestCase
{
    #[Test]
    public function theFetchStopsAtTheMaxBytesOfCore(): void
    {
        // When / Then
        static::assertSame(MetadataFetcherInterface::MAX_BYTES, new Limits()->maxBytes);
    }
}
