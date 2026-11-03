<?php

declare(strict_types=1);

namespace App\Http\Account;

use Beffroi\Core\Domain\Identity\User;

/**
 * A page of the account, as the home of the account names it (architecture §5.2): where it lives, what it
 * is called, and what the account holds there. One class per page, tagged into the wiring, so that the home
 * page reads the pages it offers from what is wired and knows no kind of credential: a page the provider or an
 * application adds is a section beside these and a line in the wiring, and nothing else is edited.
 */
interface AccountSectionInterface
{
    /**
     * The route of the page, a route of this provider.
     */
    public function route(): string;

    /**
     * The key the home page translates for the link, which is the title of the page it opens.
     */
    public function title(): string;

    /**
     * What this user holds there, said by the section itself: the one place a kind is known.
     */
    public function state(User $user): AccountSectionState;
}
