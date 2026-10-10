<?php

declare(strict_types=1);

namespace App\Account;

use function array_map;
use function array_values;
use Beffroi\Bundle\Controller\AccountArchiveController;
use Beffroi\Bundle\Controller\AccountConsentsController;
use Beffroi\Bundle\Controller\AccountNotificationsController;
use Beffroi\Bundle\Controller\AccountPasskeysController;
use Beffroi\Bundle\Controller\AccountPasswordController;
use Beffroi\Bundle\Controller\AccountProfileController;
use Beffroi\Bundle\Controller\AccountSessionsController;
use Beffroi\Bundle\Controller\AccountSignInsController;
use Beffroi\Bundle\Controller\AccountTwoFactorController;
use Beffroi\Bundle\Controller\PendingApprovalsController;
use Beffroi\Bundle\Http\Account\AccountSections;
use Beffroi\Core\Domain\Identity\User;
use function in_array;
use function is_int;

/**
 * How the navigation of this application arranges the pages of the account (architecture §5.2): the pages
 * the bundle has wired, under the heading a reader looks for each of them under. Ten links in a row is a
 * list nobody reads to the end; what somebody came for is "my data", "how I sign in", "what has happened".
 *
 * The pages are not named here, only arranged: what exists is read from AccountSections, the one object
 * that knows it, and a page this arrangement does not name is in the navigation all the same.
 */
final readonly class AccountNavigation
{
    /**
     * The headings in the order they are read, the pages each one holds and the icon each page is read by.
     *
     * A page is read under one heading or under none: what is waiting for an answer is above every heading,
     * because it is the one page that asks something of whoever opened the account rather than telling them
     * something. A page no heading names is last, under none and with no icon, so that a section the bundle
     * or this application wires is never a page the navigation drops.
     *
     * An icon is the name of a file of templates/layout/icon/, where one file draws one icon: a name no file
     * answers draws nothing, which is a link with its words and not a page nobody reaches.
     *
     * @var list<array{title: string|null, pages: array<string, string>}>
     */
    private const array HEADINGS = [
        [
            'title' => null,
            'pages' => [PendingApprovalsController::ROUTE => 'inbox'],
        ],
        [
            'title' => 'navigation.group.record',
            'pages' => [
                AccountProfileController::ROUTE => 'card',
                AccountArchiveController::ROUTE => 'archive',
            ],
        ],
        [
            'title' => 'navigation.group.sign_in',
            'pages' => [
                AccountPasswordController::ROUTE => 'lock',
                AccountPasskeysController::ROUTE => 'key',
                AccountTwoFactorController::ROUTE => 'shield',
                AccountNotificationsController::ROUTE => 'bell',
            ],
        ],
        [
            'title' => 'navigation.group.activity',
            'pages' => [
                AccountSessionsController::ROUTE => 'monitor',
                AccountConsentsController::ROUTE => 'apps',
                AccountSignInsController::ROUTE => 'history',
            ],
        ],
    ];

    /**
     * The pages whose count is read beside their link: a page that asks something of this person now says
     * how many times it is asking, where a page that tells them something is read when they open it. The
     * number is the one the section itself gives of this user and is counted nowhere here.
     *
     * @var list<string>
     */
    private const array COUNTED = [PendingApprovalsController::ROUTE];

    public function __construct(
        private AccountSections $sections,
    ) {
    }

    /**
     * The navigation, one group per heading that holds a page that is wired. The count beside a link is
     * read for the signed-in person; a page served to a browser that holds no session carries none.
     *
     * @return list<array{title: string|null, pages: list<array{route: string, title: string, icon: string|null, count: int|null}>}>
     */
    public function groups(?User $user = null): array
    {
        $wired = [];
        foreach ($this->sections->pages() as $page) {
            $wired[$page['route']] = $page;
        }

        $groups = [];
        foreach (self::HEADINGS as $heading) {
            $held = [];
            foreach ($heading['pages'] as $route => $icon) {
                if (isset($wired[$route])) {
                    $held[] = [...$wired[$route], 'icon' => $icon, 'count' => $this->countOf($route, $user)];
                    unset($wired[$route]);
                }
            }
            if ($held !== []) {
                $groups[] = [
                    'title' => $heading['title'],
                    'pages' => $held,
                ];
            }
        }

        if ($wired !== []) {
            $groups[] = [
                'title' => null,
                'pages' => array_values(array_map(
                    static fn (array $page): array => [...$page, 'icon' => null, 'count' => null],
                    $wired,
                )),
            ];
        }

        return $groups;
    }

    /**
     * How many times a page is asking, when it is one of the pages that say so and there is somebody to
     * ask: nothing to say is no number at all, and never a zero beside a link.
     */
    private function countOf(string $route, ?User $user): ?int
    {
        if ($user === null || !in_array($route, self::COUNTED, true)) {
            return null;
        }
        $count = $this->sections->stateOf($route, $user)?->parameters['count'] ?? null;

        return is_int($count) && $count > 0 ? $count : null;
    }
}
