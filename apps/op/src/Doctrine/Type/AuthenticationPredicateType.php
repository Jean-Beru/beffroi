<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Beffroi\Core\Domain\Session\AuthenticationPredicateInterface;
use Beffroi\Core\Port\AuthenticationPredicatesInterface;
use LogicException;

/**
 * The floor of the logins of a tenant (decision 0025), kept as the name the predicate gives itself and
 * read back as the class the wiring holds for that name, exactly as the algorithm of a stored hash is
 * (decision 0002). A name nothing wired carries is a row this deployment cannot account for, and it says
 * so at load instead of handing back a floor nobody named.
 *
 * @extends StringObjectType<AuthenticationPredicateInterface>
 */
final class AuthenticationPredicateType extends StringObjectType implements NeedsAuthenticationPredicatesInterface
{
    public const string NAME = 'beffroi_authentication_predicate';

    private static ?AuthenticationPredicatesInterface $predicates = null;

    public static function resolveWith(AuthenticationPredicatesInterface $predicates): void
    {
        self::$predicates = $predicates;
    }

    protected function encode(object $value): string
    {
        return $value->name();
    }

    protected function decode(string $value): object
    {
        $predicates =
            self::$predicates ?? throw new LogicException('The authentication predicates have not been handed to the DBAL type; the kernel does it when it boots.');

        return $predicates->named($value);
    }

    protected function expects(): string
    {
        return AuthenticationPredicateInterface::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
