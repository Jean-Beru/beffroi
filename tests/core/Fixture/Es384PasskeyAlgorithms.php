<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Bridge\Webauthn\PasskeyAlgorithms;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Psr\Clock\ClockInterface;
use Webauthn\AttestationStatement\AttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\PublicKeyCredentialParameters;

final readonly class Es384PasskeyAlgorithms implements PasskeyAlgorithms
{
    public function parameters(): array
    {
        return [PublicKeyCredentialParameters::createPk(ES384::ID)];
    }

    public function verifiers(): Manager
    {
        return Manager::create()->add(ES384::create());
    }

    public function tpm(ClockInterface $clock): TPMAttestationStatementSupport
    {
        return TPMAttestationStatementSupport::create($clock);
    }

    public function attestation(AttestationStatementSupport $support): AttestationStatementSupport
    {
        return $support;
    }
}
