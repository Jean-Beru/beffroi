<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Application\Session\StoredAuthenticationContextPolicy;
use Beffroi\Core\Domain\Session\AuthenticationContextPolicy;
use Beffroi\Core\Port\AuthenticationPredicatesInterface;
use LogicException;

/**
 * The "acr" policy of a tenant (decision 0010) in one JSON column, as the core writes a stored policy
 * (`StoredAuthenticationContextPolicy`): its classes in order, each a name on a predicate of the provider,
 * read back as the class the wiring holds for that name.
 *
 * The handoff through a static is the Doctrine half: Doctrine builds a type from a class name, so nothing
 * can be injected here; what reads the document takes the wiring as an argument, and this hands it the one
 * the bundle gave it when it booted.
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
        return self::policies()->document($value);
    }

    protected function decode(array $data): object
    {
        return self::policies()->of($data);
    }

    protected function expects(): string
    {
        return AuthenticationContextPolicy::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }

    private static function policies(): StoredAuthenticationContextPolicy
    {
        return new StoredAuthenticationContextPolicy(
            self::$predicates ?? throw new LogicException('The authentication predicates have not been handed to the DBAL type; the bundle does it when it boots.'),
        );
    }
}
