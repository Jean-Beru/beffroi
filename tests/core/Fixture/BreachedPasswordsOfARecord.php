<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Credential\BreachCount;
use Beffroi\Core\Domain\Credential\PasswordDigest;
use Beffroi\Core\Exception\BreachLookupFailedException;
use Beffroi\Core\Port\BreachedPasswordsInterface;
use SensitiveParameter;

/**
 * A list of compromised passwords that answers the counts it was given, zero for everything else, and
 * says which digests it was asked. What a rule about a breached password is tested against is which digest
 * reaches a list and what is made of the answer, never what Pwned Passwords holds: **no test of any suite
 * reaches the network**, here as in the bridge's own test, where a MockHttpClient answers.
 *
 * Three answers are asked of it, which are the three a list has: a count, nothing asked for a deployment
 * that names no list, and the exception of a list that could not be asked.
 *
 * A unit test builds the one it wants; a functional test is handed the one of the container and arms it,
 * which is what the mutators are for. It names no list until something names one, so a kernel that wires
 * it is a deployment that asks nobody until a test says otherwise.
 */
final class BreachedPasswordsOfARecord implements BreachedPasswordsInterface
{
    /**
     * @var list<string> the digests asked about, in order
     */
    public private(set) array $asked = [];

    /**
     * @param array<string, int> $counts how many times the list counts each digest, by its forty characters
     * @param bool $looksUp false for a deployment that names no list: nothing is asked and nothing is known
     * @param bool $unreachable true for a list that answers nothing a caller can use
     */
    public function __construct(
        private array $counts = [],
        private bool $looksUp = true,
        private bool $unreachable = false,
    ) {
    }

    /**
     * The list that holds the passwords named, each counted once.
     *
     * @param list<string> $passwords
     */
    public static function holding(array $passwords): self
    {
        return new self()->names($passwords);
    }

    /**
     * A list of this deployment, holding the passwords named and nothing else.
     *
     * @param list<string> $passwords
     */
    public function names(array $passwords): self
    {
        $this->counts = [];
        foreach ($passwords as $password) {
            $this->counts[PasswordDigest::of($password)->value] = 1;
        }
        $this->looksUp = true;
        $this->unreachable = false;

        return $this;
    }

    /**
     * A list named and unreachable, which is the unknown decision 0006 refuses to read as an answer.
     */
    public function cannotBeReached(): self
    {
        $this->looksUp = true;
        $this->unreachable = true;

        return $this;
    }

    /**
     * A deployment that names no list: it poses passwords and signs people in without asking anybody.
     */
    public function namesNothing(): self
    {
        $this->counts = [];
        $this->looksUp = false;
        $this->unreachable = false;

        return $this;
    }

    public function looksUp(): bool
    {
        return $this->looksUp;
    }

    public function timesSeen(#[SensitiveParameter] PasswordDigest $digest): BreachCount
    {
        $this->asked[] = $digest->value;
        if (! $this->looksUp) {
            return BreachCount::nothingAsked();
        }
        if ($this->unreachable) {
            throw new BreachLookupFailedException('The list of compromised passwords could not be reached.');
        }

        return BreachCount::times($this->counts[$digest->value] ?? 0);
    }
}
