<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Account;

use function array_values;
use Beffroi\Core\Domain\Identity\User;
use LogicException;
use function sprintf;

/**
 * The pages of the account this integration serves, in the order they are wired (architecture §5.2): the one
 * source of truth over them, which the home of the account renders, which the navigation of these pages is
 * drawn from, and which nothing else enumerates. Two sections on one route is a fault of the wiring, never
 * of a request.
 */
final readonly class AccountSections
{
    /**
     * @var list<AccountSectionInterface>
     */
    private array $sections;

    /**
     * @param iterable<AccountSectionInterface> $sections
     *
     * @throws LogicException when two sections name one route
     */
    public function __construct(iterable $sections)
    {
        $wired = [];
        foreach ($sections as $section) {
            $route = $section->route();
            if (isset($wired[$route])) {
                throw new LogicException(sprintf('Two sections of the account name the route "%s".', $route));
            }
            $wired[$route] = $section;
        }
        $this->sections = array_values($wired);
    }

    /**
     * What the home page renders for this user: one line per page of the account, in the order of the wiring.
     *
     * @return list<array{route: string, title: string, state: AccountSectionState}>
     */
    public function of(User $user): array
    {
        $lines = [];
        foreach ($this->sections as $section) {
            $lines[] = [
                'route' => $section->route(),
                'title' => $section->title(),
                'state' => $section->state($user),
            ];
        }

        return $lines;
    }

    /**
     * What the account holds in one of its pages, for a navigation that says it beside the link: the state
     * the section on that route gives of this user, or null when no section is on that route. One section
     * is asked, and not the nine the home of the account reads.
     */
    public function stateOf(string $route, User $user): ?AccountSectionState
    {
        foreach ($this->sections as $section) {
            if ($section->route() === $route) {
                return $section->state($user);
            }
        }

        return null;
    }

    /**
     * Where the pages of the account are and what they are called, in the order of the wiring: what a
     * navigation of these pages is drawn from, which asks no section what the account holds there, that
     * being read on the home and on each page itself.
     *
     * @return list<array{route: string, title: string}>
     */
    public function pages(): array
    {
        $pages = [];
        foreach ($this->sections as $section) {
            $pages[] = [
                'route' => $section->route(),
                'title' => $section->title(),
            ];
        }

        return $pages;
    }
}
