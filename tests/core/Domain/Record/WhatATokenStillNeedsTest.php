<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Record;

use Beffroi\Core\Domain\Record\WhatATokenStillNeeds;
use DateInterval;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class WhatATokenStillNeedsTest extends TestCase
{
    #[Test]
    public function theTwoLifetimesAreBothSubtracted(): void
    {
        // Given
        $retention = new WhatATokenStillNeeds(new DateInterval('P90D'), new DateInterval('PT600S'));

        // When / Then
        static::assertEquals(
            new DateTimeImmutable('2026-07-12T09:50:00+00:00'),
            $retention->deadBefore(new DateTimeImmutable('2026-10-10T10:00:00+00:00')),
        );
    }
}
