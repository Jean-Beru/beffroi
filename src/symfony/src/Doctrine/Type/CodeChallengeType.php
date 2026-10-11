<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Oidc\Application\Authorization\StoredCodeChallenge;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Port\CodeChallengeMethodsInterface;
use LogicException;

/**
 * The PKCE challenge (RFC 7636 §4.3) in one column, because it may be absent (decision 0008) and an
 * embeddable cannot be null. What the column holds, "method:challenge", and the method read back as the
 * class the wiring holds for that name, is the module's own (`StoredCodeChallenge`).
 *
 * The handoff through a static is the Doctrine half: Doctrine builds a type from a class name, so nothing
 * can be injected here; what reads the value takes the wiring as an argument, and this hands it the one
 * the bundle gave it when it booted.
 *
 * @extends StringObjectType<CodeChallenge>
 */
final class CodeChallengeType extends StringObjectType implements NeedsCodeChallengeMethodsInterface
{
    public const string NAME = 'beffroi_code_challenge';

    private static ?CodeChallengeMethodsInterface $methods = null;

    public static function resolveWith(CodeChallengeMethodsInterface $methods): void
    {
        self::$methods = $methods;
    }

    protected function encode(object $value): string
    {
        return self::challenges()->document($value);
    }

    protected function decode(string $value): object
    {
        return self::challenges()->of($value);
    }

    protected function expects(): string
    {
        return CodeChallenge::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }

    private static function challenges(): StoredCodeChallenge
    {
        return new StoredCodeChallenge(
            self::$methods ?? throw new LogicException('The code challenge methods have not been handed to the DBAL type; the bundle does it when it boots.'),
        );
    }
}
