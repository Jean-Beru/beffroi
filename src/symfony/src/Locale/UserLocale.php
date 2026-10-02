<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Locale;

use Beffroi\Core\Domain\Identity\User;

/**
 * The language this provider writes to a user in when there is no request of theirs to read one from
 * (architecture §5.7): what they told this provider they read, when this deployment has it, and the
 * default locale otherwise.
 *
 * It is one object because every channel that reaches a user asks the same question
 * (PendingApprovalChannelInterface), and a second channel or a second kind of message deciding for itself
 * is two answers for one user. The locale of an interaction is not this: a browser in front of a page is
 * answered from that request, "ui_locales" then "Accept-Language" (InteractionLocale), and neither exists
 * here.
 *
 * "locale" is a claim of OIDC Core §5.1 and not a setting of this provider: it is what a user or an
 * upstream provider said, so it may be absent, may be a tag nobody here serves, and is read as a language
 * rather than taken as one (ServedLocales).
 */
final readonly class UserLocale
{
    public function __construct(
        private ServedLocales $served,
    ) {
    }

    public function of(User $user): string
    {
        $claimed = $user->profile->locale;

        return ($claimed === null ? null : $this->served->match([$claimed])) ?? $this->served->default;
    }
}
