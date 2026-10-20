<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Bundle\Doctrine\TenantNotSynchronizedException;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Message\RefreshTheServiceProviderMetadata;
use Beffroi\Saml\Application\ServiceProvider\ServiceProviderMetadataRefresh;
use Psr\Log\LoggerInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * The hourly refresh of the metadata of the service providers (beffroi/saml, spec/saml.md section 6.2), the same
 * object the console calls (`beffroi:saml:service-provider:refresh`): what differs is who reads the outcome, a
 * terminal there and a log here.
 *
 * It fails nothing. A location that cannot be reached and a document refused are written to the log as errors, the
 * level an operator is alerted on, and taken again at the next tick, the document accepted serving meanwhile, until
 * its own validUntil refuses it (spec/saml.md S-6): a refusal nobody reads would keep that document for as long.
 */
#[AsMessageHandler(bus: 'command.bus')]
final readonly class RefreshTheServiceProviderMetadataHandler
{
    public function __construct(
        private TenantProvider $tenants,
        private ServiceProviderMetadataRefresh $refresh,
        private LoggerInterface $logger,
    ) {
    }

    public function __invoke(RefreshTheServiceProviderMetadata $message): void
    {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException) {
            // before the first provisioning there is no tenant to serve, and a tick is not the place to say so
            return;
        }
        foreach ($this->refresh->refreshAll($tenant) as $refreshment) {
            if ($refreshment->refused) {
                $this->logger->error($refreshment->what);
                continue;
            }
            $this->logger->info($refreshment->what);
        }
    }
}
