<?php

declare(strict_types=1);

namespace App\Twig;

use App\Http\InteractionLocale;
use App\Locale\ServedLocales;
use Symfony\Component\HttpFoundation\RequestStack;
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
        private RequestStack $requests,
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

    /**
     * The languages this visitor may choose between, which is none when the record of a person answered
     * the language of this page (issue #485): somebody who is signed in reads these pages in the language
     * their record names, and changes it where that record is changed. So the control is for whoever is
     * not known yet, and a control that offers nothing is not rendered, which is the rule it already
     * follows under two languages.
     *
     * @return list<string>
     */
    #[AsTwigFunction(name: 'beffroi_locale_choice')]
    public function choice(): array
    {
        $request = $this->requests->getMainRequest();

        return $request?->attributes->getBoolean(InteractionLocale::OF_THE_ACCOUNT) === true ? [] : $this->served->all;
    }
}
