<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\Webauthn;

use Heidi\Core\Bridge\Webauthn\WebauthnCeremonies;
use Heidi\Core\Exception\PasskeyCeremonyFailedException;
use Heidi\Core\Tests\Fixture\Fixtures;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Clock\MockClock;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * What the two ceremonies share: the relying party and the origin are the tenant's (WebAuthn Level 3
 * §5.4.2, §13.4.9), the options travel as the JSON the browser parses (§5.1.8).
 */
final class WebauthnCeremoniesTest extends TestCase
{
    #[Test]
    #[DataProvider('provideIssuers')]
    public function theRelyingPartyIsTheHostOfTheIssuerAndTheOriginTheIssuerWithoutItsPath(string $issuer, string $relyingPartyId, string $origin): void
    {
        // Given
        $tenant = Fixtures::tenant(issuer: $issuer);

        // When / Then
        static::assertSame($relyingPartyId, WebauthnCeremonies::relyingPartyId($tenant));
        static::assertSame($origin, WebauthnCeremonies::origin($tenant));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideIssuers(): iterable
    {
        yield 'a host' => ['https://id.acme.example', 'id.acme.example', 'https://id.acme.example'];
        yield 'a host and a path' => ['https://acme.example/id', 'acme.example', 'https://acme.example'];
        yield 'a loopback host with a port' => ['http://127.0.0.1:8080', '127.0.0.1', 'http://127.0.0.1:8080'];
    }

    #[Test]
    public function theOptionsAreSerialisedForTheBrowser(): void
    {
        // Given
        $ceremonies = new WebauthnCeremonies(new MockClock());
        $options = PublicKeyCredentialRequestOptions::create(str_repeat("\xff", 32), 'id.acme.example', userVerification: 'preferred');

        // When
        $json = $ceremonies->optionsToJson($options);

        // Then
        static::assertSame([
            'challenge' => str_repeat('_', 42) . '8',
            'rpId' => 'id.acme.example',
            'allowCredentials' => [],
            'userVerification' => 'preferred',
        ], json_decode($json, true, 8, JSON_THROW_ON_ERROR));
    }

    #[Test]
    public function aResponseTheLibraryCannotReadIsAFailureOfTheCeremony(): void
    {
        // Given
        $ceremonies = new WebauthnCeremonies(new MockClock());

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The response of the browser cannot be read');

        // When
        $ceremonies->credentialFromJson('{"id":"a","rawId":"b","type":"public-key","response":{}}');
    }
}
