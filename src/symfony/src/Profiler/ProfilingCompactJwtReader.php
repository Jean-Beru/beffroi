<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Profiler;

use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Port\CompactJwtReaderInterface;

/**
 * Every JWT a third party sent the provider, as the provider read it: the request object that carries an
 * authorization request (RFC 9101 §4), the assertion that authenticates a client (RFC 7523 §2.2) and the
 * proof of possession of a key (RFC 9449 §4.2) all come in this way. Nothing here says the signature was
 * good; a verifier speaks afterwards, and what the panel shows is what arrived.
 *
 * This is what stops being readable from the outside once a request is signed: the header names the
 * algorithm and the key, and the claims are the request itself. Neither is a secret, both are what the
 * sender chose to put on the wire; a claim that names a credential all the same is withheld.
 */
final readonly class ProfilingCompactJwtReader implements CompactJwtReaderInterface
{
    public function __construct(
        private CompactJwtReaderInterface $jwts,
        private OpProfile $profile,
        private PanelValues $values,
    ) {
    }

    public function read(string $jwt): UnverifiedJwt
    {
        $read = $this->jwts->read($jwt);
        $this->profile->record(new Observation('Request', 'JWT received, not yet verified', [
            'alg' => $read->algorithm() ?? 'none declared',
            'kid' => $read->keyId() ?? 'none declared',
            'typ' => self::header($read, 'typ'),
            'claims' => $this->values->all($read->claims),
        ]));

        return $read;
    }

    private static function header(UnverifiedJwt $jwt, string $name): string
    {
        $value = $jwt->protectedHeader[$name] ?? null;

        return $value === null ? 'none declared' : WithheldValues::of($name, $value);
    }
}
