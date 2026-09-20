<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use function array_map;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationContextPolicy;
use Heidi\Core\Domain\Session\AuthenticationPredicate;
use function is_array;
use function is_string;

/**
 * The "acr" policy of a tenant (decision 0010) as a JSON object holding its classes in order, each a name
 * on a predicate of the provider; a list rather than an object keyed by name, because "1" and "2" are
 * names and JSON object keys that look like numbers come back as integers.
 *
 * @extends JsonObjectType<AuthenticationContextPolicy>
 */
final class AuthenticationContextPolicyType extends JsonObjectType
{
    public const string NAME = 'heidi_authentication_context_policy';

    protected function encode(object $value): array
    {
        return [
            'classes' => array_map(static fn (AuthenticationContextClass $class): array => [
                'name' => $class->value,
                'predicate' => $class->predicate->value,
            ], $value->classes),
        ];
    }

    protected function decode(array $data): object
    {
        $classes = [];
        foreach (is_array($data['classes'] ?? null) ? $data['classes'] : [] as $entry) {
            $name = is_array($entry) ? ($entry['name'] ?? null) : null;
            $predicate = is_array($entry) ? ($entry['predicate'] ?? null) : null;
            if (! is_string($name) || ! is_string($predicate) || AuthenticationPredicate::tryFrom($predicate) === null) {
                throw ValueNotConvertible::new($data, self::NAME, 'An authentication context policy lists classes, each a name on a predicate of the provider.');
            }
            $classes[] = new AuthenticationContextClass($name, AuthenticationPredicate::from($predicate));
        }

        return new AuthenticationContextPolicy($classes);
    }

    protected function expects(): string
    {
        return AuthenticationContextPolicy::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
