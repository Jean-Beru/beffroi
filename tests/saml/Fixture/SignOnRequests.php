<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Domain\SingleSignOn\SignOnRequest;
use DateTimeImmutable;

final readonly class SignOnRequests
{
    public const string ID = '_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b';

    public const string ASSERTION_CONSUMER = ServiceProviderDocuments::SIGNED . '/acs';

    public static function request(
        ?string $relayState = 'state-1',
        bool $forceAuthn = false,
        bool $isPassive = false,
        ?string $nameIdFormat = null,
        bool $authnContextRequested = false,
        ?DateTimeImmutable $receivedAt = null,
        string $serviceProvider = ServiceProviderDocuments::SIGNED,
    ): SignOnRequest {
        return new SignOnRequest(
            $serviceProvider,
            self::ID,
            self::ASSERTION_CONSUMER,
            $relayState,
            $forceAuthn,
            $isPassive,
            $nameIdFormat,
            $authnContextRequested,
            $receivedAt ?? Fixtures::now(),
        );
    }
}
