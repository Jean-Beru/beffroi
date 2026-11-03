<?php

declare(strict_types=1);

namespace App\Profiler;

use function in_array;
use function is_scalar;
use function str_ends_with;

/**
 * Which named values of the protocol carry a credential, written once for everything the panel prints:
 * a parameter a client sent, a member an endpoint answered, a claim a document holds. Whoever holds one
 * of these holds what it names, so the panel says it is there and never what it is, whether it arrived
 * or left, and whether the provider wrote it or read it.
 *
 * It is a rule of the protocol and not of the wiring: "access_token" is a bearer credential wherever it
 * is written (RFC 6749 §1.4), and so is everything that ends in "_token", everything that hands one over
 * as a hint ("id_token_hint", OIDC Core §3.1.2.1), an authorization code, a verifier, a secret, an
 * assertion and a request object. So is what stands for a request in progress, which its specification
 * asks to resist guessing: the two codes of the device grant (RFC 8628 §3.2, §5.1, §5.2) and the
 * verification URI that carries the user code (§3.3.1), the identifier of a backchannel request
 * (CIBA Core §7.3) and the reference of a pushed request (RFC 9126 §2.2, §7.1). "user_code" is also the
 * secret of the user a backchannel request may carry (CIBA Core §7.1).
 */
final readonly class WithheldValues
{
    private const array NAMES = [
        'token',
        'code',
        'code_verifier',
        'client_secret',
        'request',
        'client_assertion',
        'dpop',
        'device_code',
        'user_code',
        'verification_uri_complete',
        'auth_req_id',
        'request_uri',
    ];

    public static function withholds(string $name): bool
    {
        return in_array($name, self::NAMES, true) || str_ends_with($name, '_token') || str_ends_with($name, '_token_hint');
    }

    /**
     * What the panel prints for one named value: the value when it names no credential, that it is there
     * otherwise, and a structure is named rather than spelled out.
     */
    public static function of(string $name, mixed $value): string
    {
        if (self::withholds($name)) {
            return '(present, withheld)';
        }

        return is_scalar($value) ? (string) $value : '(a structure, withheld)';
    }
}
