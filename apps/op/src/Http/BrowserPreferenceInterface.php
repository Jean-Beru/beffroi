<?php

declare(strict_types=1);

namespace App\Http;

/**
 * One preference of a browser (architecture §5.7): the slot it occupies on the cookie of the preferences,
 * and the reading of what that slot holds.
 *
 * One class per preference, tagged into the wiring, so that a preference the provider or an application adds
 * is a slot declared beside these and nothing else edited: no second cookie, and no list of names kept
 * beside the objects that read them. What is wired is what the cookie carries, which is why a slot nobody
 * declared is read as nothing at all.
 */
interface BrowserPreferenceInterface
{
    /**
     * The name of its slot on the cookie, unique among the preferences that are wired.
     */
    public function slot(): string;

    /**
     * What the slot holds, canonical, and null when nobody here serves it: a cookie somebody wrote by hand
     * names something this deployment has or names nothing. It is the one place the values of a preference
     * are known, and it is asked of what is read and of what is about to be written.
     */
    public function read(string $value): ?string;
}
