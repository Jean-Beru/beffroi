<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use function array_map;
use Beffroi\Oidc\Application\Client\Registration\RegistrationHeldToItsSector;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Beffroi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Port\SectorIdentifiersInterface;
use Beffroi\Oidc\Tests\Fixture\FakeSectorIdentifierDocumentFetcher;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\Shapes;
use function hrtime;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;

/**
 * OIDC Registration §5
 */
final class RegistrationHeldToItsSectorTest extends TestCase
{
    #[Test]
    public function aSectorListingFiftyThousandUrisHoldsAClientPublishingAsManyInLessThanASecond(): void
    {
        // Given
        $uris = array_map(static fn (int $index): string => 'https://rp.example/cb/' . $index, range(1, 50_000));
        $registration = new ClientRegistration(
            'many',
            new ClientPresentation('Many'),
            Methods::none(),
            false,
            [new RedirectUri('https://rp.example/cb/1')],
            Shapes::jwt(),
            sectorIdentifierUri: new ClientUri('https://rp.example/sector.json'),
        );
        $sectors = $this->createStub(SectorIdentifiersInterface::class);
        $sectors->method('publishedUris')->willReturn($uris);
        $held = new RegistrationHeldToItsSector(new FakeSectorIdentifierDocumentFetcher($uris), $sectors);

        // When
        $start = hrtime(true);
        $held->assertHolds($registration, new ClientMetadata([new RegisteredMembers([])]));
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertLessThan(1_000, $milliseconds);
    }
}
