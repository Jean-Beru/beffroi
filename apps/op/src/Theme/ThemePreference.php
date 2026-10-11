<?php

declare(strict_types=1);

namespace App\Theme;

use Beffroi\Bundle\Http\BrowserPreferenceInterface;
use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

/**
 * The theme a visitor asked for (issue #447): the slot it holds on the cookie of the preferences of a
 * browser, which the bundle owns, and the reading of what that slot carries.
 *
 * The slot is declared here and the cookie is not: the look of the pages is the decision of whoever
 * installs the bundle (architecture §6), and a preference of an application is a slot tagged beside the
 * ones the bundle wires, never a cookie of its own.
 */
#[AutoconfigureTag('beffroi.browser_preference')]
final readonly class ThemePreference implements BrowserPreferenceInterface
{
    public const string SLOT = 'theme';

    public function slot(): string
    {
        return self::SLOT;
    }

    /**
     * A theme this deployment has, and null for anything else, which leaves the browser to answer: the
     * absence of a choice and a choice nobody serves are one thing (Theme::ofChoice()).
     */
    public function read(string $value): ?string
    {
        return Theme::tryFrom($value)?->value;
    }
}
