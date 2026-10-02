<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Twig;

use Beffroi\Bundle\Locale\ServedLocales;
use Twig\Attribute\AsTwigFunction;

/**
 * What the control of the language reads (issue #448, architecture §5.7): the languages this deployment
 * serves, in the order of "framework.enabled_locales" with the default in front, which is the one list
 * every reading of a tag goes through. A page compares them with the locale of the request, which the
 * listener of the interaction plane has already set from that same list.
 */
final readonly class LocaleExtension
{
    public function __construct(
        private ServedLocales $served,
    ) {
    }

    /**
     * @return list<string>
     */
    #[AsTwigFunction(name: 'beffroi_locales')]
    public function locales(): array
    {
        return $this->served->all;
    }
}
