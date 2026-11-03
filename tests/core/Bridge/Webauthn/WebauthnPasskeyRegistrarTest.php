<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Webauthn;

use function array_map;
use Beffroi\Core\Bridge\InMemory\InMemoryMetadataBlobStore;
use Beffroi\Core\Bridge\Webauthn\WebauthnCeremonies;
use Beffroi\Core\Bridge\Webauthn\WebauthnPasskeyRegistrar;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\PasskeyCeremonyFailedException;
use Beffroi\Core\Tests\Fixture\Ed25519SoftwareKey;
use Beffroi\Core\Tests\Fixture\Es256SoftwareKey;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\MetadataBlobs;
use Beffroi\Core\Tests\Fixture\Rs1SoftwareKey;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use Beffroi\Core\Tests\Fixture\SoftwareCredentialKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;
use Symfony\Component\Uid\Uuid;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;

/**
 * The registration ceremony of WebAuthn Level 3 §7.1 on webauthn-lib, answered by a software authenticator.
 */
final class WebauthnPasskeyRegistrarTest extends TestCase
{
    private Tenant $tenant;

    private User $alice;

    private WebauthnCeremonies $ceremonies;

    private WebauthnPasskeyRegistrar $registrar;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->ceremonies = Fixtures::ceremonies();
        $this->registrar = new WebauthnPasskeyRegistrar($this->ceremonies);
    }

    /**
     * §5.4: the relying party is the tenant, the user entity carries the handle, a passkey is discoverable
     * (§5.4.6), user verification preferred, no attestation asked for (§5.4.7).
     */
    #[Test]
    public function theCreationOptionsAreThoseOfAPasskeyOfTheTenant(): void
    {
        // Given
        $handle = Fixtures::userHandle();

        // When
        $options = $this->registrar->creationOptions($this->alice, $handle, []);

        // Then
        static::assertSame('id.acme.example', $options->rp->id);
        static::assertSame($handle->value, $options->user->id);
        static::assertSame('alice', $options->user->name);
        static::assertSame('alice', $options->user->displayName);
        static::assertSame(32, strlen($options->challenge));
        static::assertSame(
            [-7, -8, -257],
            array_map(static fn (PublicKeyCredentialParameters $parameters): int => $parameters->alg, $options->pubKeyCredParams),
        );
        static::assertSame('required', $options->authenticatorSelection?->residentKey);
        static::assertSame('preferred', $options->authenticatorSelection->userVerification);
        static::assertNull($options->authenticatorSelection->authenticatorAttachment);
        static::assertSame('none', $options->attestation);
        static::assertSame([], $options->excludeCredentials);
    }

    #[Test]
    public function theDisplayNameIsTheNameOfTheProfileWhenThereIsOne(): void
    {
        // Given
        $this->alice->updateProfile(new Profile(name: 'Alice Martin'), Fixtures::now());

        // When
        $options = $this->registrar->creationOptions($this->alice, Fixtures::userHandle(), []);

        // Then
        static::assertSame('Alice Martin', $options->user->displayName);
    }

    #[Test]
    public function eachCallDrawsAnotherChallenge(): void
    {
        // Given
        $handle = Fixtures::userHandle();

        // When
        $first = $this->registrar->creationOptions($this->alice, $handle, []);
        $second = $this->registrar->creationOptions($this->alice, $handle, []);

        // Then
        static::assertNotSame($first->challenge, $second->challenge);
    }

    /**
     * §5.4, excludeCredentials: the passkeys given, with their transports.
     */
    #[Test]
    public function theExistingPasskeysAreExcluded(): void
    {
        // Given
        $handle = Fixtures::userHandle();
        $existing = [
            Fixtures::passkey($this->alice, credentialId: 'first', userHandle: $handle),
            Fixtures::passkey($this->alice, credentialId: 'second', userHandle: $handle),
        ];

        // When
        $options = $this->registrar->creationOptions($this->alice, $handle, $existing);

        // Then
        static::assertSame(
            ['first', 'second'],
            array_map(static fn (PublicKeyCredentialDescriptor $descriptor): string => $descriptor->id, $options->excludeCredentials),
        );
        static::assertSame(['usb'], $options->excludeCredentials[0]->transports);
    }

    /**
     * §7.1: the record of the new credential, the flags of the authenticator data kept.
     */
    #[Test]
    #[DataProvider('provideAuthenticators')]
    public function anAttestationOfTheTenantIsVerifiedIntoARecord(bool $backupEligible, bool $backedUp): void
    {
        // Given
        $authenticator = new SoftwareAuthenticator('https://id.acme.example', backupEligible: $backupEligible, backedUp: $backedUp);
        $options = $this->registrar->creationOptions($this->alice, Fixtures::userHandle(), []);

        // When
        $record = $this->registrar->verifyAttestation($this->tenant, $options, $authenticator->create($this->ceremonies->optionsToJson($options)));

        // Then
        static::assertSame($authenticator->credentialId, $record->publicKeyCredentialId);
        static::assertSame($authenticator->cosePublicKey(), $record->credentialPublicKey);
        static::assertSame($options->user->id, $record->userHandle);
        static::assertSame('none', $record->attestationType);
        static::assertSame(0, $record->counter);
        static::assertSame($backupEligible, $record->backupEligible);
        static::assertSame($backedUp, $record->backupStatus);
        static::assertSame($authenticator->aaguid, $record->aaguid->toBinary());
    }

    /**
     * @return iterable<string, array{bool, bool}>
     */
    public static function provideAuthenticators(): iterable
    {
        yield 'a hardware key' => [false, false];
        yield 'a synced passkey' => [true, true];
    }

    /**
     * §7.1, step 21, and the spike README: an attestation statement the authenticator sends although none
     * was asked for is verified, here a packed one in self attestation (§8.2).
     */
    #[Test]
    public function anAttestationStatementSentAnywayIsVerified(): void
    {
        // Given
        $authenticator = new SoftwareAuthenticator('https://id.acme.example', attestation: 'packed');
        $options = $this->creationOptions();

        // When
        $record = $this->registrar->verifyAttestation($this->tenant, $options, $authenticator->create($this->ceremonies->optionsToJson($options)));

        // Then
        static::assertSame('self', $record->attestationType);
        static::assertSame($authenticator->credentialId, $record->publicKeyCredentialId);
    }

    /**
     * Decision 0033: a passkey of an algorithm the options offer enrols, its packed self attestation (§8.2)
     * verified with that algorithm.
     */
    #[Test]
    #[DataProvider('provideKeysOfTheOfferedAlgorithms')]
    public function aPasskeyOfAnAlgorithmTheOptionsOfferIsEnrolled(SoftwareCredentialKey $key): void
    {
        // Given
        $authenticator = new SoftwareAuthenticator('https://id.acme.example', attestation: 'packed', credentialKey: $key);
        $options = $this->creationOptions();

        // When
        $record = $this->registrar->verifyAttestation($this->tenant, $options, $authenticator->create($this->ceremonies->optionsToJson($options)));

        // Then
        static::assertSame('self', $record->attestationType);
        static::assertSame($authenticator->cosePublicKey(), $record->credentialPublicKey);
    }

    /**
     * @return iterable<string, array{SoftwareCredentialKey}>
     */
    public static function provideKeysOfTheOfferedAlgorithms(): iterable
    {
        yield 'ES256' => [new Es256SoftwareKey()];
        yield 'EdDSA over Ed25519' => [new Ed25519SoftwareKey()];
    }

    /**
     * Decision 0033 and §7.1 (CheckAlgorithm): the ceremonies verify RS1 and the options never offer it, so a
     * passkey of that algorithm does not enrol through the product.
     */
    #[Test]
    public function aPasskeyOfAnAlgorithmTheOptionsDoNotOfferIsRefused(): void
    {
        // Given
        $authenticator = new SoftwareAuthenticator('https://id.acme.example', credentialKey: new Rs1SoftwareKey());
        $options = $this->creationOptions();

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The attestation was refused');

        // When
        $this->registrar->verifyAttestation($this->tenant, $options, $authenticator->create($this->ceremonies->optionsToJson($options)));
    }

    /**
     * §5.4.7: the provider asks for no attestation, so the library consults no metadata (§7.1 step 22 is
     * for an attestation asked for), and an authenticator the metadata say is compromised enrols all the
     * same; the spike README: an attestation is never required. A policy that refuses is the hosted
     * offer's, on the same metadata.
     */
    #[Test]
    public function theMetadataAreNotConsultedWhenNoAttestationWasAskedFor(): void
    {
        // Given
        $authenticator = new SoftwareAuthenticator('https://id.acme.example', attestation: 'packed');
        $store = new InMemoryMetadataBlobStore();
        $store->write('mds', MetadataBlobs::payload([MetadataBlobs::entry(
            Uuid::fromBinary($authenticator->aaguid)->toRfc4122(),
            [AuthenticatorStatus::USER_VERIFICATION_BYPASS],
        )]));
        $ceremonies = Fixtures::ceremonies($store);
        $registrar = new WebauthnPasskeyRegistrar($ceremonies);
        $options = $registrar->creationOptions($this->alice, Fixtures::userHandle(), []);

        // When
        $record = $registrar->verifyAttestation($this->tenant, $options, $authenticator->create($ceremonies->optionsToJson($options)));

        // Then
        static::assertSame('self', $record->attestationType);
    }

    #[Test]
    public function anAttestationStatementThatDoesNotHoldIsRefused(): void
    {
        // Given
        $authenticator = new SoftwareAuthenticator('https://id.acme.example', attestation: 'packed', forgesAttestation: true);
        $options = $this->creationOptions();

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The attestation was refused');

        // When
        $this->registrar->verifyAttestation($this->tenant, $options, $authenticator->create($this->ceremonies->optionsToJson($options)));
    }

    #[Test]
    public function anAttestationFromAnotherOriginIsRefused(): void
    {
        // Given
        $authenticator = new SoftwareAuthenticator('https://phishing.example');
        $options = $this->creationOptions();

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The attestation was refused');

        // When
        $this->registrar->verifyAttestation($this->tenant, $options, $authenticator->create($this->ceremonies->optionsToJson($options)));
    }

    /**
     * §13.4.9: the origin is the whole of it, port included; the issuer of the tenant names it.
     */
    #[Test]
    public function anAttestationFromTheSameHostOnAnotherPortIsRefused(): void
    {
        // Given
        $authenticator = new SoftwareAuthenticator('https://id.acme.example:8443');
        $options = $this->creationOptions();

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The attestation was refused');

        // When
        $this->registrar->verifyAttestation($this->tenant, $options, $authenticator->create($this->ceremonies->optionsToJson($options)));
    }

    #[Test]
    public function anAttestationScopedToAnotherRelyingPartyIsRefused(): void
    {
        // Given
        $authenticator = new SoftwareAuthenticator('https://id.acme.example', relyingPartyId: 'acme.example');
        $options = $this->creationOptions();

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The attestation was refused');

        // When
        $this->registrar->verifyAttestation($this->tenant, $options, $authenticator->create($this->ceremonies->optionsToJson($options)));
    }

    /**
     * §7.1, step 8: the challenge of the response is the one of the options.
     */
    #[Test]
    public function anAttestationOfAnotherChallengeIsRefused(): void
    {
        // Given
        $authenticator = new SoftwareAuthenticator('https://id.acme.example');
        $options = $this->creationOptions();
        $response = $authenticator->create($this->ceremonies->optionsToJson($this->creationOptions()));

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The attestation was refused');

        // When
        $this->registrar->verifyAttestation($this->tenant, $options, $response);
    }

    /**
     * §7.1, step 14: a user must be present at creation.
     */
    #[Test]
    public function anAttestationWithoutUserPresenceIsRefused(): void
    {
        // Given
        $authenticator = new SoftwareAuthenticator('https://id.acme.example', userPresent: false);
        $options = $this->creationOptions();

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The attestation was refused');

        // When
        $this->registrar->verifyAttestation($this->tenant, $options, $authenticator->create($this->ceremonies->optionsToJson($options)));
    }

    #[Test]
    public function anAssertionIsNotAnAttestation(): void
    {
        // Given
        $authenticator = new SoftwareAuthenticator('https://id.acme.example');
        $options = $this->creationOptions();
        $authenticator->create($this->ceremonies->optionsToJson($options));
        $assertion = $authenticator->get('{"challenge":"' . str_repeat('A', 43) . '","rpId":"id.acme.example"}');

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIs('The response of the browser is not the attestation of a new passkey.');

        // When
        $this->registrar->verifyAttestation($this->tenant, $options, $assertion);
    }

    #[Test]
    public function aResponseThatIsNotACredentialIsRefused(): void
    {
        // Given
        $options = $this->creationOptions();

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The response of the browser cannot be read');

        // When
        $this->registrar->verifyAttestation($this->tenant, $options, 'not json');
    }

    private function creationOptions(): PublicKeyCredentialCreationOptions
    {
        return $this->registrar->creationOptions($this->alice, Fixtures::userHandle(), []);
    }
}
