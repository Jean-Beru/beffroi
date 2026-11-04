<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Authorization\CodeChallengeMethods;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;

/**
 * RFC 7636 §4.2
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
