<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Account;

use function array_values;
use Beffroi\Core\Domain\Identity\User;
use LogicException;
use function sprintf;

/**
 * The pages of the account this integration serves, in the order they are wired (architecture §5.2): the one
 * source of truth over them, which the home of the account renders and which nothing else enumerates. Two
 * sections on one route is a fault of the wiring, never of a request.
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
}
