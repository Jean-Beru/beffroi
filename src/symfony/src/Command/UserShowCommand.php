<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use function array_filter;
use function array_map;
use DateTimeImmutable;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Credential\RevocableCredentialInterface;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use function implode;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * A user as the provider knows them (architecture §5.5): the identity, the standard claims that are set,
 * and the credentials with their kind, identifier, name and dates. Reads, writes nothing: describing a
 * user is beffroi:user:profile, and that one clears what it is not told.
 */
#[AsCommand(
    name: 'beffroi:user:show',
    description: 'Show a user: the identity, the standard claims that are set, and the credentials with their kind, identifier, name and dates.',
)]
final readonly class UserShowCommand
{
    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private CredentialRepositoryInterface $credentials,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the user.')]
        string $username,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        $user = $this->namedUsers->orTold($io, $tenant, $username);
        if ($user === null) {
            return Command::FAILURE;
        }

        $io->definitionList(...self::identity($user), ...self::claims($user));

        $io->section('Credentials');
        $credentials = $this->credentials->findByUser($user);
        if ($credentials === []) {
            $io->text('The user has no credential.');
        } else {
            $io->table(
                ['Kind', 'Id', 'Name', 'Created', 'Last used', 'Revoked'],
                array_map(static fn (Credential $credential): array => [
                    $credential->kind(),
                    $credential->id->toRfc4122(),
                    $credential->label() ?? '',
                    self::date($credential->createdAt),
                    self::date($credential->lastUsedAt),
                    $credential instanceof RevocableCredentialInterface ? self::date($credential->revokedAt) : '',
                ], $credentials),
            );
        }

        return Command::SUCCESS;
    }

    /**
     * @return list<array<string, string>>
     */
    private static function identity(User $user): array
    {
        return [
            [
                'Username' => $user->username,
            ],
            [
                'Subject' => $user->subject->value,
            ],
            [
                'Status' => $user->isEnabled() ? 'enabled' : sprintf('disabled since %s', self::date($user->disabledAt)),
            ],
            [
                'Created' => self::date($user->createdAt),
            ],
            [
                'Email' => $user->email === null ? '' : sprintf('%s (%s)', $user->email, $user->emailVerified ? 'verified' : 'unverified'),
            ],
        ];
    }

    /**
     * The standard claims of OIDC Core §5.1 the user has, as beffroi:user:profile prints what it wrote.
     *
     * @return list<array<string, string>>
     */
    public static function claims(User $user): array
    {
        return [
            [
                'Name' => $user->profile->name ?? '',
            ],
            [
                'Given name' => $user->profile->givenName ?? '',
            ],
            [
                'Family name' => $user->profile->familyName ?? '',
            ],
            [
                'Phone number' => $user->phoneNumber === null
                    ? ''
                    : sprintf('%s (%s)', $user->phoneNumber, $user->phoneNumberVerified ? 'verified' : 'unverified'),
            ],
            [
                'Address' => $user->address === null
                    ? ''
                    : implode(', ', array_filter(
                        [
                            $user->address->streetAddress,
                            $user->address->postalCode,
                            $user->address->locality,
                            $user->address->region,
                            $user->address->country,
                        ],
                        static fn (?string $member): bool => $member !== null,
                    )),
            ],
        ];
    }

    private static function date(?DateTimeImmutable $date): string
    {
        return $date?->format('Y-m-d H:i:s') ?? '';
    }
}
