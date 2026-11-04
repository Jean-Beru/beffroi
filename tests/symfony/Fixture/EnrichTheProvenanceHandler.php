<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use Beffroi\Core\Domain\Session\Device;
use Beffroi\Core\Domain\Session\DeviceType;
use Beffroi\Core\Domain\Session\GeoLocation;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;

/**
 * Decision 0018
 */
final readonly class EnrichTheProvenanceHandler
{
    public const string CITY = 'Oxford';

    public const string BROWSER = 'Firefox';

    public function __construct(
        private AuthenticationSessionRepositoryInterface $sessions,
    ) {
    }

    public function __invoke(EnrichTheProvenance $message): void
    {
        $session = $this->sessions->find($message->sessionId);
        if ($session === null) {
            return;
        }

        $enriched = $session
            ->lastSeenFrom
            ->withLocation(new GeoLocation('GB', 'England', self::CITY, 64_268, 'Example Networks', 51.752, -1.2577))
            ->withDevice(new Device(DeviceType::Desktop, self::BROWSER, '140.0', 'Linux'));

        $session->touch($enriched, $session->expiresAt);
        $this->sessions->save($session);
    }
}
