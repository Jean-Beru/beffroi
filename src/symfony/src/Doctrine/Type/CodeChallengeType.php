<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use function explode;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function sprintf;
use function str_contains;

/**
 * The PKCE challenge of an authorization request (RFC 7636 §4.3), as "method:challenge" in one column,
 * because an authorization request or a code may carry none when the client does not require PKCE
 * (decision 0008), and an embeddable cannot be null.
 *
 * @extends StringObjectType<CodeChallenge>
 */
final class CodeChallengeType extends StringObjectType
{
    public const string NAME = 'heidi_code_challenge';

    protected function encode(object $value): string
    {
        return sprintf('%s:%s', $value->method->value, $value->value);
    }

    protected function decode(string $value): object
    {
        if (! str_contains($value, ':')) {
            throw new InvalidArgumentException(sprintf('A stored code challenge reads "method:challenge", got "%s".', $value));
        }
        [$method, $challenge] = explode(':', $value, 2);
        $case = CodeChallengeMethod::tryFrom($method);
        if ($case === null) {
            throw new InvalidArgumentException(sprintf('The code challenge method "%s" is not one of the provider.', $method));
        }

        return new CodeChallenge($challenge, $case);
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
