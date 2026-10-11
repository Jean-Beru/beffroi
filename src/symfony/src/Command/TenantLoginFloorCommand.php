<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Core\Application\Tenant\TenantHardening;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Port\AuthenticationPredicatesInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * The floor of every login of the tenant, named without a redeploy (issue #327): a tenant that moves to
 * passkeys names the phishing-resistant predicate and its users sign in by passkey and by nothing else,
 * the password, the one-time codes and the backup codes they held being forgotten with it.
 *
 * It is the command the console of the tenant will press the same use case with (TenantHardening, epic
 * #194): everything the console does, a command does, and both call the one use case rather than two
 * copies of a policy. The floor is written on the row and not in the configuration, where the "acr"
 * vocabulary of the tenant lives: hardening is an act with a date, and a deployment that redeployed to
 * get one would have no date to show.
 */
#[AsCommand(
    name: self::NAME,
    description: 'Name the floor of every login of the tenant, and forget the credentials it forbids.',
)]
final readonly class TenantLoginFloorCommand
{
    public const string NAME = 'beffroi:tenant:login-floor';

    public function __construct(
        private ConfiguredTenant $tenant,
        private TenantHardening $hardening,
        private RequestContextFactory $contexts,
        private AuthenticationPredicatesInterface $predicates,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(
            description: 'The predicate every login must satisfy, by the name that predicate gives itself. The predicates are the ones this provider is wired with; a name none of them carries is refused with the ones that are.',
        )]
        string $floor,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        // The registry words the refusal, with what this provider does carry: the name of a predicate is
        // resolved here exactly as it is in the configuration of a tenant and in a stored policy.
        try {
            $named = $this->predicates->named($floor);
        } catch (InvalidArgumentException $exception) {
            $io->error($exception->getMessage());

            return Command::INVALID;
        }
        if ($named->name() === $tenant->loginFloor->name()) {
            $io->success(sprintf('Every login of the tenant "%s" already proves "%s" at the least.', $tenant->slug, $named->name()));

            return Command::SUCCESS;
        }
        $io->definitionList(
            [
                'Tenant' => $tenant->slug,
            ],
            [
                'Floor now' => $tenant->loginFloor->name(),
            ],
            [
                'Floor asked' => $named->name(),
            ],
        );
        if (! $io->confirm(sprintf(
            'Every credential of this tenant that proves nothing "%s" reads is forgotten, secret and row, and has to be posed again. Continue?',
            $named->name(),
        ), false)) {
            $io->warning('Nothing was changed.');

            return Command::INVALID;
        }

        $forgotten = $this->hardening->adopt($tenant, $named, $this->contexts->fromConsole(self::NAME));
        $io->success(sprintf(
            'Every login of the tenant "%s" proves "%s" at the least; %d credential%s forgotten.',
            $tenant->slug,
            $named->name(),
            $forgotten,
            $forgotten === 1 ? ' was' : 's were',
        ));

        return Command::SUCCESS;
    }
}
