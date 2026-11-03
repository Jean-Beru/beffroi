<?php

declare(strict_types=1);

namespace App\Http;

use function count;
use Beffroi\Oidc\Domain\Dpop\DpopProof;
use Beffroi\Oidc\Exception\InvalidDpopProofException;
use function is_string;
use Symfony\Component\HttpFoundation\Request;

/**
 * The proof a request carries (RFC 9449 §4.1): the one DPoP header, or none. A request carrying two is
 * refused here and not arbitrated (§4.3): which of them the provider read would decide which key the
 * tokens of the response are bound to, and nothing in the request says which one the client meant.
 */
final readonly class DpopProofHeader
{
    /**
     * @throws InvalidDpopProofException when the request carries more than one proof
     */
    public static function ofRequest(Request $request): ?string
    {
        $proofs = $request->headers->all(DpopProof::HEADER);
        if (count($proofs) > 1) {
            throw new InvalidDpopProofException('The request carries more than one DPoP header (RFC 9449 section 4.3).');
        }
        $proof = $proofs[0] ?? null;

        return is_string($proof) && $proof !== '' ? $proof : null;
    }
}
