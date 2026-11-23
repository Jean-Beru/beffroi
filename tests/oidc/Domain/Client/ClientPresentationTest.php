<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client;

use function array_map;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use function hrtime;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;

/**
 * OIDC Registration §2
 */
final class ClientPresentationTest extends TestCase
{
    #[Test]
    public function aContactNamedTwiceCountsOnceWhereItWasFirstNamed(): void
    {
        // When
        $presentation = new ClientPresentation('Contacts', contacts: ['ops@rp.example', 'dpo@rp.example', 'ops@rp.example']);

        // Then
        static::assertSame(['ops@rp.example', 'dpo@rp.example'], $presentation->contacts);
    }

    #[Test]
    public function itKeepsFiftyThousandDistinctContactsInLessThanASecond(): void
    {
        // Given
        $contacts = array_map(static fn (int $index): string => 'ops' . $index . '@rp.example', range(1, 50_000));

        // When
        $start = hrtime(true);
        $presentation = new ClientPresentation('Contacts', contacts: $contacts);
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertCount(50_000, $presentation->contacts);
        static::assertLessThan(1_000, $milliseconds);
    }
}
