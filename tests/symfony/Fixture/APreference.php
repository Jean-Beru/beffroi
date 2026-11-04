<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use App\Http\BrowserPreferenceInterface;
use function in_array;

final readonly class APreference implements BrowserPreferenceInterface
{
    /**
     * @param list<string> $values
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
