<?php

declare(strict_types=1);

namespace App\Security;

use function is_array;
use LogicException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Throwable;

/**
 * A code the TOTP authenticator of the provider refused, carrying what the code page is allowed to say of
 * it (CodeRefusal) and nothing of the reason the core gave, which belongs to the audit trail alone. The
 * security component keeps the exception in the HTTP session for the page to read once: the refusal is
 * serialized with it, the way AuthenticationException asks a subclass to extend its state, and a
 * serialised form this class did not write is refused, as with SecurityUser.
 */
final class CodeRefusedException extends BadCredentialsException
{
    public function __construct(
        public readonly CodeRefusal $refusal,
        ?Throwable $previous = null,
    ) {
        parent::__construct('The code was refused.', 0, $previous);
    }

    /**
     * @return array{CodeRefusal, array<array-key, mixed>}
     */
    public function __serialize(): array
    {
        return [$this->refusal, parent::__serialize()];
    }

    /**
     * @param array<array-key, mixed> $data
     *
     * @throws LogicException when the state is not the one __serialize() wrote
     */
    public function __unserialize(array $data): void
    {
        $refusal = $data[0] ?? null;
        $parentData = $data[1] ?? null;
        if (! $refusal instanceof CodeRefusal || ! is_array($parentData)) {
            throw new LogicException('The serialised refusal is not one this class wrote.');
        }
        $this->refusal = $refusal;
        parent::__unserialize($parentData);
    }
}
