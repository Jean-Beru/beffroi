<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use function array_map;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Oidc\Domain\Interaction\StepUp;

/**
 * What the login page says of a step-up (decision 0010): the classes the request would accept, and the
 * kinds of credential this user holds that would reach one. Two lists of words, which is all a page shows
 * of a StepUp and all that survives the session of a browser.
 *
 * It exists because the two pages that ask for one more proof do not hold the same thing. The login page
 * of an interaction is handed the decision the module just made; the page where a user answers a request
 * made for them somewhere else (CIBA Core §10.1) sends the browser to that same login and is not there
 * when it arrives, so what it is asking for is written into the session of that browser (LoginTarget).
 */
final readonly class StepUpOffer
{
    /**
     * @param non-empty-list<string> $classes the requested classes, in the order the client preferred them
     * @param non-empty-list<string> $kinds the kinds of credential that would satisfy one, each once
     */
    public function __construct(
        public array $classes,
        public array $kinds,
    ) {
    }

    public static function of(StepUp $stepUp): self
    {
        return new self(
            array_map(static fn (AuthenticationContextClass $class): string => $class->value, $stepUp->classes),
            $stepUp->kinds(),
        );
    }
}
