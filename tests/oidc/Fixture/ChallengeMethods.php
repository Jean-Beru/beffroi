<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Oidc\Application\Authorization\CodeChallengeMethods;
use Heidi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;

/**
 * The PKCE methods the tests wire (RFC 7636 §4.2): the one the bundle wires, which decision 0006 holds
 * every deployment to, and that one beside a method a deployment invented, for what a provider announces
 * and takes when the wiring holds two.
 */
final readonly class ChallengeMethods
{
    public static function s256(): CodeChallengeMethods
    {
        return new CodeChallengeMethods([new Sha256CodeChallengeMethod()]);
    }

    public static function s256AndInvented(): CodeChallengeMethods
    {
        return new CodeChallengeMethods([new Sha256CodeChallengeMethod(), new FakeCodeChallengeMethod()]);
    }
}
