<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\Geo\GeoLite2Refresh;
use App\Message\RefreshTheAddressDatabases;
use Psr\Log\LoggerInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * The weekly refresh of the databases of addresses (issue #473), the same object the console calls
 * (`beffroi:geoip:refresh`): what differs is who reads the outcome, a terminal there and a log here.
 *
 * It fails nothing. A source that cannot be reached, a licence key that expired and an archive that is
 * not one are written to the log and taken again next week, because what is late here is the place a
 * provenance says and nothing a person is waiting for.
 */
#[AsMessageHandler(bus: 'command.bus')]
final readonly class RefreshTheAddressDatabasesHandler
{
    public function __construct(
        private GeoLite2Refresh $refresh,
        private LoggerInterface $logger,
    ) {
    }

    public function __invoke(RefreshTheAddressDatabases $message): void
    {
        foreach ($this->refresh->refresh() as $refreshment) {
            if ($refreshment->refused) {
                $this->logger->warning($refreshment->what);
                continue;
            }
            $this->logger->info($refreshment->what);
        }
    }
}
