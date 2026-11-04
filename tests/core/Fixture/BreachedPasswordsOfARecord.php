<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Credential\BreachCount;
use Beffroi\Core\Domain\Credential\PasswordDigest;
use Beffroi\Core\Exception\BreachLookupFailedException;
use Beffroi\Core\Port\BreachedPasswordsInterface;
use SensitiveParameter;

final class BreachedPasswordsOfARecord implements BreachedPasswordsInterface
{
    /**
     * @var list<string>
     */
    public private(set) array $asked = [];

    /**
     * @param array<string, int> $counts the count of each digest, keyed by its forty characters
     */
    public function __construct(
        private array $counts = [],
        private bool $looksUp = true,
        private bool $unreachable = false,
    ) {
    }

    /**
     * @param list<string> $passwords
     */
    public static function holding(array $passwords): self
    {
        return new self()->names($passwords);
    }

    /**
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

    public function cannotBeReached(): self
    {
        $this->looksUp = true;
        $this->unreachable = true;

        return $this;
    }

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
