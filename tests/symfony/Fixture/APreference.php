<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use App\Http\BrowserPreferenceInterface;
use function in_array;

/**
 * A preference of a browser decided by the test: a slot and the values it serves. The provider wires one
 * preference, the language, and this is what stands in for the two things one slot cannot show: a second
 * slot left alone while the first is written, and a slot an application declares.
 */
final readonly class APreference implements BrowserPreferenceInterface
{
    /**
     * @param list<string> $values what it serves, anything else being read as nothing
     */
    public function __construct(
        private string $slot,
        private array $values,
    ) {
    }

    public function slot(): string
    {
        return $this->slot;
    }

    public function read(string $value): ?string
    {
        return in_array($value, $this->values, true) ? $value : null;
    }
}
