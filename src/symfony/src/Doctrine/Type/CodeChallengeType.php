<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use function explode;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\CodeChallengeMethodsInterface;
use LogicException;
use function sprintf;
use function str_contains;

/**
 * The PKCE challenge (RFC 7636 §4.3) as "method:challenge" in one column, because it may be absent
 * (decision 0008) and an embeddable cannot be null. The method is written under the name it gives itself
 * and read back as the class the wiring holds for that name, exactly as the algorithm of a stored hash is
 * (decision 0002): a challenge this deployment is not wired to verify is refused rather than guessed.
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
        return sprintf('%s:%s', $value->method->name(), $value->value);
    }

    protected function decode(string $value): object
    {
        if (! str_contains($value, ':')) {
            throw new InvalidArgumentException(sprintf('A stored code challenge reads "method:challenge", got "%s".', $value));
        }
        [$name, $challenge] = explode(':', $value, 2);
        $methods =
            self::$methods ?? throw new LogicException('The code challenge methods have not been handed to the DBAL type; the bundle does it when it boots.');
        $method = $methods->codeChallengeMethodNamed($name);
        if ($method === null) {
            throw new InvalidArgumentException(sprintf('The code challenge method "%s" is not one of the provider.', $name));
        }

        return new CodeChallenge($challenge, $method);
    }

    protected function expects(): string
    {
        return CodeChallenge::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
