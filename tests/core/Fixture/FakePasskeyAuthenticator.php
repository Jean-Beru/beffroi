<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Fixture;

use function array_map;
use Heidi\Core\Domain\Credential\PasskeyCredential;
use Heidi\Core\Domain\Credential\VerifiedPasskeyAssertion;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\PasskeyCeremonyFailedException;
use Heidi\Core\Port\PasskeyAuthenticatorInterface;
use function str_repeat;
use Webauthn\AuthenticatorData;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * An authentication ceremony that trusts the test: the assertion is verified as prepared, or refused.
 */
final class FakePasskeyAuthenticator implements PasskeyAuthenticatorInterface
{
    /**
     * @var list<PublicKeyCredentialDescriptor>
     */
    public private(set) array $allowed = [];

    private ?PasskeyCredential $credential = null;

    private ?AuthenticatorData $authenticatorData = null;

    private ?string $refusal = null;

    public function verifies(PasskeyCredential $credential, AuthenticatorData $authenticatorData): void
    {
        $this->credential = $credential;
        $this->authenticatorData = $authenticatorData;
    }

    public function refuses(string $message): void
    {
        $this->refusal = $message;
    }

    public function requestOptions(Tenant $tenant, array $allowed): PublicKeyCredentialRequestOptions
    {
        $this->allowed = array_map(static fn (PasskeyCredential $passkey): PublicKeyCredentialDescriptor => $passkey
            ->record()
            ->getPublicKeyCredentialDescriptor(), $allowed);

        return PublicKeyCredentialRequestOptions::create(str_repeat('c', 32), rpId: 'id.acme.example', allowCredentials: $this->allowed);
    }

    public function verifyAssertion(Tenant $tenant, PublicKeyCredentialRequestOptions $options, string $response): VerifiedPasskeyAssertion
    {
        if ($this->refusal !== null || $this->credential === null || $this->authenticatorData === null) {
            throw new PasskeyCeremonyFailedException($this->refusal ?? 'No assertion was prepared.');
        }

        return new VerifiedPasskeyAssertion($this->credential, $this->authenticatorData);
    }
}
