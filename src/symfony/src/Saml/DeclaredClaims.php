<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Saml\Port\ServedClaimsInterface;
use function is_array;
use function is_string;

/**
 * The claims the declarations of service providers map, served as they are named (beffroi/saml, spec/saml.md S-16,
 * section 6.2 step 1). What the provider serves comes from the claims providers the container builds, which a compiler
 * pass has not built: ServiceProvidersPass builds the declarations with this when the container is compiled, so that
 * every other rule of a declaration fails the compilation, and MappedClaimsWarmer checks the claim of a mapping against
 * the claims of the provider right after, in the same build. It reads no user and gives no value.
 */
final readonly class DeclaredClaims implements ServedClaimsInterface
{
    /**
     * @param list<string> $names
     */
    private function __construct(
        private array $names,
    ) {
    }

    /**
     * The claim of every attribute mapping the declarations hold; what is not a mapping is left to the constructors of
     * the declaration, which refuse it.
     *
     * @param array<array-key, mixed> $declarations
     */
    public static function mappedBy(array $declarations): self
    {
        $names = [];
        foreach ($declarations as $declaration) {
            $attributes = is_array($declaration) ? $declaration['attributes'] ?? null : null;
            if (! is_array($attributes)) {
                continue;
            }
            foreach ($attributes as $attribute) {
                $claim = is_array($attribute) ? $attribute['claim'] ?? null : null;
                if (is_string($claim)) {
                    $names[] = $claim;
                }
            }
        }

        return new self($names);
    }

    public function names(): array
    {
        return $this->names;
    }

    public function of(User $user, array $names): array
    {
        return [];
    }
}
