<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use Heidi\Core\Application\Identity\UserAlreadyExistsException;
use Heidi\Core\Application\Identity\UserProvisioner;
use Heidi\Core\Domain\Identity\EmailAddress;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Exception\InvalidArgumentException;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * A user of the tenant (architecture §3.1, §5.5); the subject is generated unless an import brings one (decision 0002).
 */
#[AsCommand(
    name: 'heidi:user:create',
    description: 'Create a user of the tenant; give them a password with heidi:user:set-password.',
)]
final readonly class UserCreateCommand
{
    public function __construct(
        private ConfiguredTenant $tenant,
        private UserProvisioner $provisioner,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'What the user types to name themselves; unique in the tenant.')]
        string $username,
        #[Option(description: 'The email address of the user, unverified unless said otherwise.')]
        ?string $email = null,
        #[Option(description: 'The email address was verified by whoever provisions the user.')]
        bool $emailVerified = false,
        #[Option(description: 'The "sub" the clients know the user by, when importing an identity; generated otherwise.')]
        ?string $subject = null,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }

        try {
            $user = $this->provisioner->create(
                $tenant,
                $username,
                $email === null ? null : new EmailAddress($email),
                $emailVerified,
                $subject === null ? null : new Subject($subject),
            );
        } catch (InvalidArgumentException $exception) {
            $io->error($exception->getMessage());

            return Command::INVALID;
        } catch (UserAlreadyExistsException $exception) {
            $io->error($exception->getMessage());

            return Command::FAILURE;
        }

        $io->definitionList(
            [
                'Username' => $user->username,
            ],
            [
                'Subject' => $user->subject->value,
            ],
            [
                'Email' => $user->email === null ? '' : sprintf('%s (%s)', $user->email, $user->emailVerified ? 'verified' : 'unverified'),
            ],
            [
                'Identifier' => $user->id->toRfc4122(),
            ],
            [
                'Tenant' => $tenant->slug,
            ],
        );
        $io->success(sprintf('The user "%s" is created; give them a password with "heidi:user:set-password %s".', $user->username, $user->username));

        return Command::SUCCESS;
    }
}
