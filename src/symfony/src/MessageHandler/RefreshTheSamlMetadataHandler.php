<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Bundle\Doctrine\TenantNotSynchronizedException;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Message\RefreshTheSamlMetadata;
use Beffroi\Saml\Application\Metadata\MetadataRefresh;
use Beffroi\Saml\Domain\Metadata\PeerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * The hourly refresh of the metadata of the SAML peers of the tenant (beffroi/saml, spec/saml.md sections 6.2 and
 * 6.10), every role in the order it is wired, each by the same object its console command calls
 * (`beffroi:saml:service-provider:refresh`, `beffroi:saml:identity-provider:refresh`): what differs is who reads the
 * outcome, a terminal there and a log here. A role is one refresh tagged, and nothing here names one.
 *
 * It fails nothing. A location that cannot be reached and a document refused are written to the log as errors, the
 * level an operator is alerted on, and taken again at the next tick, the document accepted serving meanwhile, until
 * its own validUntil refuses it (spec/saml.md S-6): a refusal nobody reads would keep that document for as long.
 */
#[AsMessageHandler(bus: 'command.bus')]
final readonly class RefreshTheSamlMetadataHandler
{
    /**
     * The tag of the refresh of each role.
     */
    public const string TAG = 'beffroi.saml.metadata_refresh';

    /**
     * @param iterable<MetadataRefresh<PeerInterface>> $refreshes the refresh of every role
     */
    public function __construct(
        private TenantProvider $tenants,
        private iterable $refreshes,
        private LoggerInterface $logger,
    ) {
    }

    public function __invoke(RefreshTheSamlMetadata $message): void
    {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException) {
            // before the first provisioning there is no tenant to serve, and a tick is not the place to say so
            return;
        }
        foreach ($this->refreshes as $refresh) {
            foreach ($refresh->refreshAll($tenant) as $refreshment) {
                if ($refreshment->refused) {
                    $this->logger->error($refreshment->what);
                    continue;
                }
                $this->logger->info($refreshment->what);
            }
        }
    }
}
