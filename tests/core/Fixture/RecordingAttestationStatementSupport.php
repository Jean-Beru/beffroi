<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\AttestationStatementSupport;
use Webauthn\AuthenticatorData;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * A format that gives the answer it is built with, loads one statement whatever it is handed, and counts the
 * statements it is asked to verify.
 */
final class RecordingAttestationStatementSupport implements AttestationStatementSupport
{
    public readonly AttestationStatement $loaded;

    public private(set) int $verified = 0;

    public function __construct(
        private readonly bool $answer = true,
    ) {
        $this->loaded = AttestationStatement::createNone('recording', [], EmptyTrustPath::create());
    }

    public function name(): string
    {
        return 'recording';
    }

    public function load(array $attestation): AttestationStatement
    {
        return $this->loaded;
    }

    public function isValid(string $clientDataJSONHash, AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData): bool
    {
        ++$this->verified;

        return $this->answer;
    }
}
