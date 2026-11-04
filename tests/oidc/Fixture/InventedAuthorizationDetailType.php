<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function array_is_list;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetail;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetailTypeInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function implode;
use function is_array;
use function is_string;
use function sprintf;

/**
 * RFC 9396 §2
 */
final readonly class InventedAuthorizationDetailType implements AuthorizationDetailTypeInterface
{
    public const string TYPE = 'account_information';

    public const string ACCOUNT = 'account';

    public const string ACTIONS = 'actions';

    /**
     * @param non-empty-string $type
     */
    public function __construct(
        private string $type = self::TYPE,
    ) {
    }

    public function type(): string
    {
        return $this->type;
    }

    public function of(array $members): AuthorizationDetail
    {
        $account = $members[self::ACCOUNT] ?? null;
        if (! is_string($account) || $account === '') {
            throw new InvalidArgumentException(sprintf('A detail of the type "%s" names an account in a non-empty "account" member.', $this->type));
        }
        $actions = self::actions($members);

        return new AuthorizationDetail(
            $this->type,
            [
                self::ACCOUNT => $account,
                self::ACTIONS => $actions,
            ],
            [
                self::ACCOUNT => $account,
                self::ACTIONS => implode(', ', $actions),
            ],
        );
    }

    /**
     * @param array<string, mixed> $members
     *
     * @throws InvalidArgumentException
     *
     * @return non-empty-list<string>
     */
    private function actions(array $members): array
    {
        $actions = $members[self::ACTIONS] ?? null;
        if (! is_array($actions) || ! array_is_list($actions) || $actions === []) {
            throw new InvalidArgumentException(sprintf(
                'A detail of the type "%s" names what it asks of the account in a non-empty "actions" list.',
                $this->type,
            ));
        }
        $kept = [];
        foreach ($actions as $action) {
            if (! is_string($action) || $action === '') {
                throw new InvalidArgumentException(sprintf('The actions of a detail of the type "%s" are non-empty strings.', $this->type));
            }
            $kept[] = $action;
        }

        return $kept;
    }
}
