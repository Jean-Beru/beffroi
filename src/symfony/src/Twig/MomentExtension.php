<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Twig;

use Beffroi\Bundle\Locale\UserTimeZone;
use Beffroi\Core\Domain\Identity\User;
use DateTimeImmutable;
use IntlDateFormatter;
use Symfony\Component\Translation\LocaleSwitcher;
use Twig\Attribute\AsTwigFilter;

/**
 * A moment as the person in front of the page reads it (issue #469): in the language the page is written
 * in, on the clock that person keeps, and **always saying which clock that is**, because an hour without
 * its zone is an hour a reader cannot check.
 *
 * The language decides the order and the words, which is ICU's answer and not ours: a date is not a
 * string to translate, it is a convention of a locale, and a deployment that serves a language it wrote
 * no catalogue entry for still gets that language's dates. The clock is one field added to the pattern
 * that language gives, so the shape stays the locale's and nothing of it is rewritten here.
 *
 * It takes the person rather than reading one, because a page that shows a date always knows whose page
 * it is, and a filter that went looking for a session would answer for the wrong reader on a page someone
 * else is being shown. Nobody given, the clock of the deployment answers.
 */
final readonly class MomentExtension
{
    /**
     * What a moment looks like where ICU cannot write one: the instant and its zone, in the one shape
     * every language reads the same way (ISO 8601). The contract of IntlDateFormatter admits a refusal,
     * and a page owes a reader a date either way.
     */
    public const string WITHOUT_ICU = 'Y-m-d H:i T';

    /**
     * The field that names the clock (CLDR, "zzz"): an abbreviation where that clock has one, its offset
     * where it has none.
     */
    private const string CLOCK = ' zzz';

    public function __construct(
        private UserTimeZone $zones,
        private LocaleSwitcher $switcher,
    ) {
    }

    #[AsTwigFilter(name: 'beffroi_moment')]
    public function moment(DateTimeImmutable $moment, ?User $reader = null): string
    {
        $zone = $this->zones->of($reader);
        $formatter = new IntlDateFormatter(
            $this->switcher->getLocale(),
            IntlDateFormatter::MEDIUM,
            IntlDateFormatter::SHORT,
            $zone,
        );
        $pattern = $formatter->getPattern();
        if ($pattern !== false) {
            $formatter->setPattern($pattern . self::CLOCK);
        }
        $written = $formatter->format($moment);

        return $written === false ? $moment->setTimezone($zone)->format(self::WITHOUT_ICU) : $written;
    }
}
