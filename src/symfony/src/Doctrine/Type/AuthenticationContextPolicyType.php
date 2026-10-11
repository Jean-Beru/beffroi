<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use function array_map;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationContextPolicy;
use Beffroi\Core\Port\AuthenticationPredicatesInterface;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use function is_array;
use function is_string;
use LogicException;

/**
 * The "acr" policy of a tenant (decision 0010) as a JSON object holding its classes in order, each a name
 * on a predicate of the provider; a list rather than an object keyed by name, because "1" and "2" are
 * names and JSON object keys that look like numbers come back as integers.
 *
 * A predicate is written under the name it gives itself and read back as the class the wiring holds for
 * that name: a policy naming a predicate this deployment is not wired with is refused rather than
 * guessed, as a stored password hash naming an algorithm nothing carries is (decision 0002).
 *
 * @extends JsonObjectType<AuthenticationContextPolicy>
 */
final class AuthenticationContextPolicyType extends JsonObjectType implements NeedsAuthenticationPredicatesInterface
{
    public const string NAME = 'beffroi_authentication_context_policy';

    private static ?AuthenticationPredicatesInterface $predicates = null;

    public static function resolveWith(AuthenticationPredicatesInterface $predicates): void
    {
        self::$predicates = $predicates;
    }

    protected function encode(object $value): array
    {
        return [
            'classes' => array_map(static fn (AuthenticationContextClass $class): array => [
                'name' => $class->value,
                'predicate' => $class->predicate->name(),
            ], $value->classes),
        ];
    }

    protected function decode(array $data): object
    {
        $predicates =
            self::$predicates ?? throw new LogicException('The authentication predicates have not been handed to the DBAL type; the bundle does it when it boots.');
        $classes = [];
        foreach (is_array($data['classes'] ?? null) ? $data['classes'] : [] as $entry) {
            $name = is_array($entry) ? $entry['name'] ?? null : null;
            $predicate = is_array($entry) ? $entry['predicate'] ?? null : null;
            if (! is_string($name) || ! is_string($predicate)) {
                throw ValueNotConvertible::new(
                    $data,
                    self::NAME,
                    'An authentication context policy lists classes, each a name on a predicate of the provider.',
                );
            }
            $classes[] = new AuthenticationContextClass($name, $predicates->named($predicate));
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
