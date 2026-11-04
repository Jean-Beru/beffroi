<?php

declare(strict_types=1);

namespace App\Key;

/**
 * How long a key works before the planning stages a successor for it (issue #455, architecture §3.3),
 * counted from its activation.
 *
 * **The default is ninety days**, and the two ends of the range say why that is the figure.
 *
 * - **The floor is not what decides it.** The longest-lived thing a key of this provider signs is an
 *   access token or an ID token, ten minutes by default (`beffroi.tokens`), so the window a retiring key
 *   holds the JWK Set open for is minutes: a key could work for a week without two of them ever being
 *   published at once. What the floor forbids is only an age shorter than that window, which the rotation
 *   refuses rather than letting the JWK Set grow at every rotation (`KeySuccession`).
 * - **The ceiling is the cryptoperiod.** NIST SP 800-57 Part 1 Rev. 5 §5.3.6 puts the originator usage
 *   period of a private signature key at one to three years, so ninety days is well inside it.
 *
 * What sets the figure between the two is neither: it is that a rotation path walked four times a year is
 * a path that works, where one walked once in the life of a deployment is first walked during an incident.
 * A deployment that knows better says so.
 */
final readonly class KeyAge
{
    public const int DEFAULT_SECONDS = 7_776_000;
}
