<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Profiler;

use Beffroi\Oidc\Port\ClaimsProviderInterface;
use function implode;
use function in_array;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;

/**
 * How one named value is written on the panel, wherever it is read: a parameter of a request, a member
 * of an answer, a claim of a document. Two rules, and they are the whole of what the panel withholds.
 *
 * A name that carries a credential is said to be there and never spelled out (WithheldValues). A name
 * the provider serves as a claim about a user is personal data, and the panel names it rather than
 * giving it (decision 0011, which spike 8 will only harden); which names those are is asked of the
 * claims provider, the same one the discovery document announces them from, so the rule follows what is
 * wired and no list is kept beside it.
 *
 * Everything else is written as it is: an issuer, an audience, an expiry, an "acr", a scope, the
 * parameters of a request object. None of them is a secret, and a panel that hid them would say nothing.
 */
final readonly class PanelValues
{
    public function __construct(
        private ClaimsProviderInterface $claims,
    ) {
    }

    public function of(string $name, mixed $value): string
    {
        if (WithheldValues::withholds($name)) {
            return '(present, withheld)';
        }
        if (in_array($name, $this->claims->supportedClaims(), true)) {
            return '(a claim about the user, named only)';
        }

        // a URL with its slashes and an accented name as it is written: this is read by a person
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * A set of named values, one per line, in the order they were written.
     *
     * @param array<array-key, mixed> $values
     */
    public function all(array $values, string $whenEmpty = 'none'): string
    {
        $written = [];
        foreach ($values as $name => $value) {
            $written[] = $name . '=' . $this->of((string) $name, $value);
        }

        return $written === [] ? $whenEmpty : implode("\n", $written);
    }
}
