<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use function array_map;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Oidc\Port\ProvableMethodsInterface;

/**
 * What the logins of an integration can prove: a password only, as spike 1 had, or a password and a
 * passkey, as the bundle wires since spike 3.
 */
final readonly class Logins implements ProvableMethodsInterface
{
    /**
     * @param non-empty-list<string> $methods
     */
    private function __construct(
        private array $methods,
    ) {
    }

    public static function passwordOnly(): self
    {
        return new self(['pwd']);
    }

    public static function passwordAndPasskey(): self
    {
        return new self(['pwd', 'hwk', 'swk', 'user', 'mfa']);
    }

    public function provableMethods(): array
    {
        return array_map(static fn (string $method): AuthenticationMethod => new AuthenticationMethod($method), $this->methods);
    }
}
