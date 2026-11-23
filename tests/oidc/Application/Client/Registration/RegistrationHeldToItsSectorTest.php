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
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Exception\SectorIdentifierUnavailableException;
use Beffroi\Oidc\Port\SectorIdentifiersInterface;
use Beffroi\Oidc\Tests\Fixture\FakeSectorIdentifierDocumentFetcher;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\Shapes;
use function hrtime;
use PHPUnit\Framework\Attributes\DataProvider;
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
        $sectors = static::createStub(SectorIdentifiersInterface::class);
        $sectors->method('publishedUris')->willReturn($uris);
        $held = new RegistrationHeldToItsSector(new FakeSectorIdentifierDocumentFetcher($uris), $sectors);

        // When
        $start = hrtime(true);
        $held->assertHolds($registration, new ClientMetadata([new RegisteredMembers([])]));
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertLessThan(1_000, $milliseconds);
    }

    /**
     * OIDC Registration §5, RFC 7591 §3.2.2
     */
    #[Test]
    #[DataProvider('provideWhatAReadMeets')]
    public function aDocumentThatCannotBeReadIsRefusedWithoutWhatTheReadMet(string $met): void
    {
        // Given
        $documents = new FakeSectorIdentifierDocumentFetcher([]);
        $documents->failure = new SectorIdentifierUnavailableException($met);
        $sectors = static::createStub(SectorIdentifiersInterface::class);
        $sectors->method('publishedUris')->willReturn(['https://rp.example/cb']);
        $held = new RegistrationHeldToItsSector($documents, $sectors);

        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIs('The document at https://10.0.0.5:8443/x cannot be read as the JSON array of redirection URIs of OIDC Registration section 5.');

        // When
        $held->assertHolds(self::registration('https://10.0.0.5:8443/x'), new ClientMetadata([new RegisteredMembers([])]));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatAReadMeets(): iterable
    {
        yield 'a port that answers' => ['https://10.0.0.5:8443/x answered 404.'];
        yield 'a port that is closed' => [
            'https://10.0.0.5:8443/x cannot be reached: Failed to connect to 10.0.0.5 port 8443 after 0 ms: Could not connect to server.',
        ];
        yield 'a service of another certificate' => ['https://10.0.0.5:8443/x cannot be reached: SSL certificate problem: self-signed certificate.'];
        yield 'an address that does not answer' => ['https://10.0.0.5:8443/x cannot be reached: Connection timed out after 3000 milliseconds.'];
        yield 'a document of another shape' => ['https://10.0.0.5:8443/x does not answer JSON.'];
    }

    private static function registration(string $sectorIdentifierUri): ClientRegistration
    {
        return new ClientRegistration(
            'attacker',
            new ClientPresentation('Attacker'),
            Methods::none(),
            false,
            [new RedirectUri('https://rp.example/cb')],
            Shapes::jwt(),
            sectorIdentifierUri: new ClientUri($sectorIdentifierUri),
        );
    }
}
