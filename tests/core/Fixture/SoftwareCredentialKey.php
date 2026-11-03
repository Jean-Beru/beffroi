<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

/**
 * The key pair of the credential a SoftwareAuthenticator creates: one algorithm, the COSE_Key of its public
 * half as the authenticator encodes it in the attested credential data (WebAuthn Level 3 §6.5.1.1), and the
 * signatures it makes with its private half.
 */
interface SoftwareCredentialKey
{
    /**
     * The COSE algorithm identifier the key signs with, as the attestation statement and the COSE_Key name it.
     */
    public function algorithm(): int;

    /**
     * The COSE_Key of the public half.
     */
    public function cosePublicKey(): string;

    /**
     * A signature over the data, as the authenticator signs.
     */
    public function sign(string $data): string;
}
