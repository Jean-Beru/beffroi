<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use Beffroi\Bundle\Webauthn\DocumentDownload;
use Beffroi\Bundle\Webauthn\DownloadRefusedException;
use Beffroi\Core\Bridge\Webauthn\AuthenticatorList;
use Beffroi\Core\Exception\AuthenticatorListRefusedException;
use Beffroi\Core\Port\AuthenticatorListStoreInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * The list of passkey providers the community keeps (architecture §3.4), refreshed by hand as the FIDO metadata
 * are: downloaded, read as that list (AuthenticatorList), stored for the page of the passkeys and the console,
 * which name the model of a passkey from it when the FIDO metadata do not. The list carries no licence, so the
 * provider ships none of it and a deployment that never ran this command names a passkey from the FIDO metadata
 * alone. A list refused, an empty one included, keeps nothing and leaves the stored one as it was.
 */
#[AsCommand(
    name: 'beffroi:webauthn:aaguids-refresh',
    description: 'Download the list of passkey providers the community keeps (names and logos by AAGUID, unsigned), refuse it unless it is that list and names one, and store it for the pages that name the authenticator of a passkey; --url for a mirror.',
)]
final readonly class WebauthnAaguidsRefreshCommand
{
    /**
     * Where the community publishes its list (github.com/passkeydeveloper/passkey-authenticator-aaguids): the
     * models it names itself, without the copy of the FIDO metadata its combined list adds.
     */
    public const string COMMUNITY_LIST = 'https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/aaguid.json';

    public function __construct(
        private DocumentDownload $download,
        private AuthenticatorListStoreInterface $store,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Option(description: 'The URL of the list; the one the community publishes unless given.')]
        ?string $url = null,
    ): int {
        $source = $url ?? self::COMMUNITY_LIST;
        try {
            $document = $this->download->of($source);
            $list = AuthenticatorList::fromJson($document);
        } catch (AuthenticatorListRefusedException|DownloadRefusedException $exception) {
            $io->error(sprintf('The list of %s is refused, nothing of it is kept and the stored one stays: %s', $source, $exception->getMessage()));

            return Command::FAILURE;
        }
        $this->store->write($document);
        $io->success(sprintf('The list of %s is stored: it names %d authenticators.', $source, $list->count()));

        return Command::SUCCESS;
    }
}
