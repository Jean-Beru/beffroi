<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function array_map;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\ProvableMethodsInterface;
use LogicException;

/**
 * What the logins of an integration can prove: a password only, as spike 1 had, or a password and a
 * passkey, as the bundle wires since spike 3.
 *
 * One list per login and not one list of methods, as the bundle reads them (PassportProofs): the floor of
 * the tenant admits a login or closes it (issue #327), and a passkey that proves "user" and "mfa" beside
 * its key is not half admitted.
 */
final readonly class Logins implements ProvableMethodsInterface
{
    /**
     * @param non-empty-list<non-empty-list<string>> $logins
     */
    private function __construct(
        private array $logins,
    ) {
    }

    public static function passwordOnly(): self
    {
        return new self([['pwd']]);
    }

    public static function passwordAndPasskey(): self
    {
        return new self([['pwd'], ['hwk', 'swk', 'user', 'mfa']]);
    }

    public function provableMethods(Tenant $tenant): array
    {
        $methods = [];
        foreach ($this->logins as $login) {
            $proven = array_map(static fn (string $method): AuthenticationMethod => new AuthenticationMethod($method), $login);
            if ($tenant->loginFloor->admits($proven)) {
                $methods = [...$methods, ...$proven];
            }
        }
        if ($methods === []) {
            throw new LogicException('The floor of the tenant admits none of these logins.');
        }

        return $methods;
    }
}
