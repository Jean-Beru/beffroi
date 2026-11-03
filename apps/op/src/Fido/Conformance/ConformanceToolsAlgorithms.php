<?php

declare(strict_types=1);

namespace App\Fido\Conformance;

use function array_map;
use Beffroi\Core\Bridge\Webauthn\PasskeyAlgorithms;
use Cose\Algorithm\Algorithm;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Psr\Clock\ClockInterface;
use Webauthn\AttestationStatement\AttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\PublicKeyCredentialParameters;

/**
 * The algorithms of the FIDO2 server API of the conformance tools (decision 0033): those of the provider,
 * then what the server tests ask a server to verify and the provider never offers.
 *
 * - ES384 (RFC 9053 §2.1), which the provider neither offers nor verifies.
 * - RS1, RSASSA-PKCS1-v1_5 with SHA-1 (RFC 8812 §2), for a self attestation and an assertion, and the TPM
 *   attestations signed with it: the tests do not mark them optional (Resp-4 P-8, Resp-9 P-2), and their
 *   weakness is acknowledged by name, here and nowhere else.
 * - The optional algorithms of the tests that are not weak: ES512, RS384, RS512, PS256, PS384 and PS512.
 *   ES256K is not among them, since the tools do not play its case.
 *
 * Nothing of the product reaches this policy: the endpoints of Fido/Conformance run on ceremonies, a
 * registrar, an authenticator and use cases of their own (services.php).
 */
final readonly class ConformanceToolsAlgorithms implements PasskeyAlgorithms
{
    public function __construct(
        private PasskeyAlgorithms $provider,
    ) {
    }

    public function parameters(): array
    {
        return [
            ...$this->provider->parameters(),
            ...array_map(
                static fn (Algorithm $algorithm): PublicKeyCredentialParameters => PublicKeyCredentialParameters::createPk($algorithm::identifier()),
                self::algorithms(),
            ),
        ];
    }

    public function verifiers(): Manager
    {
        return $this->provider->verifiers()->add(...self::algorithms());
    }

    public function tpm(ClockInterface $clock): TPMAttestationStatementSupport
    {
        return TPMAttestationStatementSupport::create($clock, acknowledgeInsecureAlgorithm: true);
    }

    public function attestation(AttestationStatementSupport $support): AttestationStatementSupport
    {
        return $support;
    }

    /**
     * @return non-empty-list<Algorithm>
     */
    private static function algorithms(): array
    {
        return [
            ES384::create(),
            RS1::create(acknowledgeInsecureAlgorithm: true),
            ES512::create(),
            RS384::create(),
            RS512::create(),
            PS256::create(),
            PS384::create(),
            PS512::create(),
        ];
    }
}
