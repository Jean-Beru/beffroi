<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Webauthn;

use Beffroi\Core\Bridge\InMemory\InMemoryMetadataBlobStore;
use Beffroi\Core\Bridge\Webauthn\ProviderPasskeyAlgorithms;
use Beffroi\Core\Bridge\Webauthn\WebauthnCeremonies;
use Beffroi\Core\Exception\PasskeyCeremonyFailedException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\MetadataBlobs;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function str_repeat;
use Symfony\Component\Uid\Uuid;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * What the two ceremonies share: the relying party and the origin are the tenant's (WebAuthn Level 3
 * §5.4.2, §13.4.9), the options travel as the JSON the browser parses (§5.1.8), and the FIDO metadata of
 * the store is what an attestation asked for is checked against (§7.1 step 22).
 */
final class WebauthnCeremoniesTest extends TestCase
{
    #[Test]
    #[DataProvider('provideIssuers')]
    public function theRelyingPartyIsTheHostOfTheIssuer(string $issuer, string $relyingPartyId): void
    {
        // Given
        $tenant = Fixtures::tenant(issuer: $issuer);

        // When / Then
        static::assertSame($relyingPartyId, WebauthnCeremonies::relyingPartyId($tenant));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideIssuers(): iterable
    {
        yield 'a host' => ['https://id.acme.example', 'id.acme.example'];
        yield 'a host and a path' => ['https://acme.example/id', 'acme.example'];
        yield 'a loopback host with a port' => ['http://127.0.0.1:8080', '127.0.0.1'];
    }

    #[Test]
    public function theOptionsAreSerialisedForTheBrowser(): void
    {
        // Given
        $ceremonies = Fixtures::ceremonies();
        $options = PublicKeyCredentialRequestOptions::create(str_repeat("\xff", 32), 'id.acme.example', userVerification: 'preferred');

        // When
        $json = $ceremonies->optionsToJson($options);

        // Then
        static::assertSame(
            [
                'challenge' => str_repeat('_', 42) . '8',
                'rpId' => 'id.acme.example',
                'allowCredentials' => [],
                'userVerification' => 'preferred',
            ],
            json_decode($json, true, 8, JSON_THROW_ON_ERROR),
        );
    }

    #[Test]
    public function aResponseTheLibraryCannotReadIsAFailureOfTheCeremony(): void
    {
        // Given
        $ceremonies = Fixtures::ceremonies();

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The response of the browser cannot be read');

        // When
        $ceremonies->credentialFromJson('{"id":"a","rawId":"b","type":"public-key","response":{}}');
    }

    /**
     * §7.1 step 22 with the metadata: the status reports of the authenticator say it is compromised, the
     * self attestation it sends when asked for one is refused.
     */
    #[Test]
    public function anAttestationAskedForIsRefusedWhenTheMetadataSayTheAuthenticatorIsCompromised(): void
    {
        // Given
        $authenticator = new SoftwareAuthenticator('https://id.acme.example', attestation: 'packed');
        $store = new InMemoryMetadataBlobStore();
        $store->write('mds', MetadataBlobs::payload([MetadataBlobs::entry(
            Uuid::fromBinary($authenticator->aaguid)->toRfc4122(),
            [AuthenticatorStatus::FIDO_CERTIFIED, AuthenticatorStatus::USER_VERIFICATION_BYPASS],
        )]));
        $ceremonies = Fixtures::ceremonies($store);
        $options = self::creationOptionsAskingForAnAttestation();
        $credential = $ceremonies->credentialFromJson($authenticator->create($ceremonies->optionsToJson($options)));
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $credential->response);

        // Then
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessageIs('The authenticator is compromised and cannot be used');

        // When
        $ceremonies->attestationValidator(Fixtures::tenant())->check($credential->response, $options, 'id.acme.example');
    }

    /**
     * An authenticator the metadata do not describe passes on a self attestation: the metadata refuse,
     * they never vouch (the spike README: an attestation is never required).
     */
    #[Test]
    public function anAttestationAskedForPassesWhenTheMetadataDoNotKnowTheAuthenticator(): void
    {
        // Given
        $authenticator = new SoftwareAuthenticator('https://id.acme.example', attestation: 'packed');
        $store = new InMemoryMetadataBlobStore();
        $store->write('mds', MetadataBlobs::payload([MetadataBlobs::entry('2fc0579f-8113-47ea-b116-bb5a8db9202a', [
            AuthenticatorStatus::USER_VERIFICATION_BYPASS,
        ])]));
        $ceremonies = Fixtures::ceremonies($store);
        $options = self::creationOptionsAskingForAnAttestation();
        $credential = $ceremonies->credentialFromJson($authenticator->create($ceremonies->optionsToJson($options)));
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $credential->response);

        // When
        $record = $ceremonies->attestationValidator(Fixtures::tenant())->check($credential->response, $options, 'id.acme.example');

        // Then
        static::assertSame('self', $record->attestationType);
        static::assertSame($authenticator->credentialId, $record->publicKeyCredentialId);
    }

    /**
     * The options a ceremony that wants an attestation draws (§5.4.7, "direct"); the provider's own
     * enrolment never does, see WebauthnPasskeyRegistrarTest.
     */
    private static function creationOptionsAskingForAnAttestation(): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('', 'id.acme.example'),
            PublicKeyCredentialUserEntity::create('alice', random_bytes(64), 'Alice'),
            random_bytes(32),
            new ProviderPasskeyAlgorithms()->parameters(),
            AuthenticatorSelectionCriteria::create(),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
        );
    }
}
