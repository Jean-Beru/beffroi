<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Webauthn;

use function array_map;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\Webauthn\WebauthnCeremonies;
use Beffroi\Core\Bridge\Webauthn\WebauthnPasskeyAuthenticator;
use Beffroi\Core\Bridge\Webauthn\WebauthnPasskeyRegistrar;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\PasskeyCeremonyFailedException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_replace;
use function strlen;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialDescriptor;

/**
 * The authentication ceremony of WebAuthn Level 3 §7.2 on webauthn-lib, answered by a software
 * authenticator enrolled through the registrar.
 */
final class WebauthnPasskeyAuthenticatorTest extends TestCase
{
    private Tenant $tenant;

    private User $alice;

    private InMemoryCredentialRepository $credentials;

    private WebauthnCeremonies $ceremonies;

    private WebauthnPasskeyAuthenticator $authenticator;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->credentials = new InMemoryCredentialRepository();
        $this->ceremonies = Fixtures::ceremonies();
        $this->authenticator = new WebauthnPasskeyAuthenticator($this->ceremonies, $this->credentials);
    }

    /**
     * §5.5: the relying party of the tenant, user verification preferred, the allow list as given.
     */
    #[Test]
    public function theRequestOptionsAreThoseOfTheTenant(): void
    {
        // Given
        $passkey = Fixtures::passkey($this->alice, credentialId: 'known');

        // When
        $options = $this->authenticator->requestOptions($this->tenant, [$passkey]);

        // Then
        static::assertSame('id.acme.example', $options->rpId);
        static::assertSame(32, strlen($options->challenge));
        static::assertSame('preferred', $options->userVerification);
        static::assertSame(['known'], array_map(static fn (PublicKeyCredentialDescriptor $descriptor): string => $descriptor->id, $options->allowCredentials));
    }

    /**
     * §5.5: no allow list for a discoverable credential, the authenticator picks (§6.3.2.1).
     */
    #[Test]
    public function theRequestOptionsForADiscoverableCredentialAllowEveryCredential(): void
    {
        // When
        $options = $this->authenticator->requestOptions($this->tenant, []);

        // Then
        static::assertSame([], $options->allowCredentials);
    }

    #[Test]
    public function eachCallDrawsAnotherChallenge(): void
    {
        // When
        $first = $this->authenticator->requestOptions($this->tenant, []);
        $second = $this->authenticator->requestOptions($this->tenant, []);

        // Then
        static::assertNotSame($first->challenge, $second->challenge);
    }

    /**
     * §7.2: the passkey of the tenant the response names, and the authenticator data it signed.
     */
    #[Test]
    #[DataProvider('provideAuthenticators')]
    public function anAssertionOfAnEnrolledPasskeyIsVerified(bool $userVerified, bool $backupEligible, int $signCount): void
    {
        // Given
        $device = new SoftwareAuthenticator('https://id.acme.example', userVerified: $userVerified, backupEligible: $backupEligible, backedUp: $backupEligible);
        $passkey = $this->enrol($device);
        $options = $this->authenticator->requestOptions($this->tenant, []);

        // When
        $assertion = $this->authenticator->verifyAssertion($this->tenant, $options, $device->get($this->ceremonies->optionsToJson($options)));

        // Then
        static::assertSame($passkey, $assertion->credential);
        static::assertTrue($assertion->authenticatorData->isUserPresent());
        static::assertSame($userVerified, $assertion->authenticatorData->isUserVerified());
        static::assertSame($backupEligible, $assertion->authenticatorData->isBackupEligible());
        static::assertSame($signCount, $assertion->authenticatorData->signCount);
    }

    /**
     * @return iterable<string, array{bool, bool, int}>
     */
    public static function provideAuthenticators(): iterable
    {
        yield 'a hardware key without a PIN' => [false, false, 1];
        yield 'a hardware key with a PIN' => [true, false, 1];
        yield 'a synced passkey' => [true, true, 0];
    }

    /**
     * The allow list of a user who named themself (§7.2, step 5).
     */
    #[Test]
    public function anAssertionOfAPasskeyOnTheAllowListIsVerified(): void
    {
        // Given
        $device = new SoftwareAuthenticator('https://id.acme.example');
        $passkey = $this->enrol($device);
        $options = $this->authenticator->requestOptions($this->tenant, [$passkey]);

        // When
        $assertion = $this->authenticator->verifyAssertion($this->tenant, $options, $device->get($this->ceremonies->optionsToJson($options)));

        // Then
        static::assertSame($passkey, $assertion->credential);
    }

    #[Test]
    public function anAssertionOfAPasskeyOffTheAllowListIsRefused(): void
    {
        // Given
        $device = new SoftwareAuthenticator('https://id.acme.example');
        $this->enrol($device);
        $options = $this->authenticator->requestOptions($this->tenant, [Fixtures::passkey($this->alice, credentialId: 'another')]);

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The assertion was refused');

        // When
        $this->authenticator->verifyAssertion($this->tenant, $options, $device->get($this->ceremonies->optionsToJson($options)));
    }

    /**
     * The sign count is the core's business (architecture §3.2): the library does not refuse it here.
     */
    #[Test]
    public function anAssertionWhoseSignCountDidNotGrowIsVerifiedAllTheSame(): void
    {
        // Given
        $device = new SoftwareAuthenticator('https://id.acme.example');
        $passkey = $this->enrol($device);
        $options = $this->authenticator->requestOptions($this->tenant, []);
        $passkey->recordUse(Fixtures::authenticatorData(signCount: 10), Fixtures::now());

        // When
        $assertion = $this->authenticator->verifyAssertion($this->tenant, $options, $device->get($this->ceremonies->optionsToJson($options)));

        // Then
        static::assertSame(1, $assertion->authenticatorData->signCount);
        static::assertTrue($passkey->signCountRegresses($assertion->authenticatorData));
    }

    /**
     * Revoked or not, the passkey is found: the core refuses it after the signature.
     */
    #[Test]
    public function anAssertionOfARevokedPasskeyIsVerifiedForTheCoreToRefuse(): void
    {
        // Given
        $device = new SoftwareAuthenticator('https://id.acme.example');
        $passkey = $this->enrol($device);
        $passkey->revoke(Fixtures::now());
        $options = $this->authenticator->requestOptions($this->tenant, []);

        // When
        $assertion = $this->authenticator->verifyAssertion($this->tenant, $options, $device->get($this->ceremonies->optionsToJson($options)));

        // Then
        static::assertSame($passkey, $assertion->credential);
    }

    /**
     * WebAuthn Level 3 §6.1.3 against webauthn-lib 5.3, which reassigns the flag and announces the change
     * instead of refusing it (web-auth/webauthn-framework#969): the comparison with the enrolment is the
     * core's, after the signature, as the sign count is.
     */
    #[Test]
    public function anAssertionWhoseBackupEligibilityChangedIsVerifiedForTheCoreToRefuse(): void
    {
        // Given
        $device = new SoftwareAuthenticator('https://id.acme.example', backupEligible: true, backedUp: true);
        $passkey = $this->enrol($device);
        $options = $this->authenticator->requestOptions($this->tenant, []);

        // When
        $assertion = $this->authenticator->verifyAssertion(
            $this->tenant,
            $options,
            $device->withoutBackupEligibility()->get($this->ceremonies->optionsToJson($options)),
        );

        // Then
        static::assertSame($passkey, $assertion->credential);
        static::assertFalse($assertion->authenticatorData->isBackupEligible());
        static::assertTrue($passkey->backupEligibilityChanged($assertion->authenticatorData));
    }

    #[Test]
    public function anAssertionOfAPasskeyOfAnotherTenantIsRefused(): void
    {
        // Given
        $device = new SoftwareAuthenticator('https://id.acme.example');
        $this->enrol($device);
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $options = $this->authenticator->requestOptions($other, []);

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIs('The response names no passkey of the tenant.');

        // When
        $this->authenticator->verifyAssertion(
            $other,
            $options,
            $device->forRelyingParty('id.other.example')->atOrigin('https://id.other.example')->get($this->ceremonies->optionsToJson($options)),
        );
    }

    #[Test]
    public function anAssertionOfAnUnknownPasskeyIsRefused(): void
    {
        // Given
        $device = new SoftwareAuthenticator('https://id.acme.example');
        $device->create($this->ceremonies->optionsToJson(new WebauthnPasskeyRegistrar($this->ceremonies)->creationOptions(
            $this->alice,
            Fixtures::userHandle(),
            [],
        )));
        $options = $this->authenticator->requestOptions($this->tenant, []);

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIs('The response names no passkey of the tenant.');

        // When
        $this->authenticator->verifyAssertion($this->tenant, $options, $device->get($this->ceremonies->optionsToJson($options)));
    }

    #[Test]
    public function anAssertionFromAnotherOriginIsRefused(): void
    {
        // Given
        $device = new SoftwareAuthenticator('https://id.acme.example');
        $this->enrol($device);
        $options = $this->authenticator->requestOptions($this->tenant, []);

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The assertion was refused');

        // When
        $this->authenticator->verifyAssertion(
            $this->tenant,
            $options,
            $device->atOrigin('https://phishing.example')->get($this->ceremonies->optionsToJson($options)),
        );
    }

    #[Test]
    public function anAssertionScopedToAnotherRelyingPartyIsRefused(): void
    {
        // Given
        $device = new SoftwareAuthenticator('https://id.acme.example');
        $this->enrol($device);
        $options = $this->authenticator->requestOptions($this->tenant, []);

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The assertion was refused');

        // When
        $this->authenticator->verifyAssertion(
            $this->tenant,
            $options,
            $device->forRelyingParty('acme.example')->get($this->ceremonies->optionsToJson($options)),
        );
    }

    /**
     * §7.2, step 12: the challenge of the response is the one of the options.
     */
    #[Test]
    public function anAssertionOfAnotherChallengeIsRefused(): void
    {
        // Given
        $device = new SoftwareAuthenticator('https://id.acme.example');
        $this->enrol($device);
        $options = $this->authenticator->requestOptions($this->tenant, []);
        $response = $device->get($this->ceremonies->optionsToJson($this->authenticator->requestOptions($this->tenant, [])));

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The assertion was refused');

        // When
        $this->authenticator->verifyAssertion($this->tenant, $options, $response);
    }

    /**
     * §7.2, step 20: the signature is checked against the public key of the record.
     */
    #[Test]
    public function anAssertionSignedByAnotherKeyIsRefused(): void
    {
        // Given
        $device = new SoftwareAuthenticator('https://id.acme.example');
        $passkey = $this->enrol($device);
        $impostor = new SoftwareAuthenticator('https://id.acme.example');
        $this->credentials->save(
            new PasskeyCredential(
                Uuid::v7(),
                $this->alice,
                'Impostor',
                $device->credentialId . '-',
                $impostor->cosePublicKey(),
                0,
                [],
                false,
                false,
                Uuid::v4(),
                $passkey->userHandle,
                Fixtures::now(),
            ),
        );
        $options = $this->authenticator->requestOptions($this->tenant, []);
        $response = str_replace(
            Base64UrlSafe::encodeUnpadded($device->credentialId) . '"',
            Base64UrlSafe::encodeUnpadded($device->credentialId . '-') . '"',
            $device->get($this->ceremonies->optionsToJson($options)),
        );

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('Invalid signature');

        // When
        $this->authenticator->verifyAssertion($this->tenant, $options, $response);
    }

    #[Test]
    public function anAttestationIsNotAnAssertion(): void
    {
        // Given
        $device = new SoftwareAuthenticator('https://id.acme.example');
        $registrar = new WebauthnPasskeyRegistrar($this->ceremonies);
        $attestation = $device->create($this->ceremonies->optionsToJson($registrar->creationOptions($this->alice, Fixtures::userHandle(), [])));
        $options = $this->authenticator->requestOptions($this->tenant, []);

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIs('The response of the browser is not the assertion of a passkey.');

        // When
        $this->authenticator->verifyAssertion($this->tenant, $options, $attestation);
    }

    #[Test]
    public function aResponseThatIsNotACredentialIsRefused(): void
    {
        // Given
        $options = $this->authenticator->requestOptions($this->tenant, []);

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The response of the browser cannot be read');

        // When
        $this->authenticator->verifyAssertion($this->tenant, $options, '[]');
    }

    /**
     * A passkey of the device, enrolled through the registrar and saved in the repository.
     */
    private function enrol(SoftwareAuthenticator $device): PasskeyCredential
    {
        $registrar = new WebauthnPasskeyRegistrar($this->ceremonies);
        $options = $registrar->creationOptions($this->alice, Fixtures::userHandle(), []);
        $record = $registrar->verifyAttestation($this->tenant, $options, $device->create($this->ceremonies->optionsToJson($options)));
        $passkey = PasskeyCredential::fromRecord(Uuid::v7(), $this->alice, 'Test key', $record, Fixtures::now());
        $this->credentials->save($passkey);

        return $passkey;
    }
}
