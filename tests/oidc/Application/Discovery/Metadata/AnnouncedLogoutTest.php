<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedLogout;
use Heidi\Oidc\Port\ServedLogoutChannelsInterface;
use Heidi\Oidc\Tests\Fixture\Endpoints;
use Heidi\Oidc\Tests\Fixture\ServedChannels;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RP-Initiated Logout §2.1: where a client sends the user to end the session. Back-Channel Logout 1.0 §3
 * and Front-Channel Logout 1.0 §3: the provider announces a channel only where something serves it, and
 * a channel it serves always carries the session (issue #98).
 */
final class AnnouncedLogoutTest extends TestCase
{
    #[Test]
    public function itNamesTheEndSessionEndpointOfTheTenant(): void
    {
        // Given
        $announced = new AnnouncedLogout(new Endpoints(), ServedChannels::both());

        // When
        $members = $announced->metadata(Fixtures::tenant('acme', 'https://as.example/acme'));

        // Then
        static::assertSame('https://as.example/acme/logout', $members['end_session_endpoint']);
    }

    #[Test]
    #[DataProvider('provideServedChannels')]
    public function theChannelsAnnouncedAreTheOnesServed(ServedLogoutChannelsInterface $served, bool $backChannel, bool $frontChannel): void
    {
        // Given
        $announced = new AnnouncedLogout(new Endpoints(), $served);

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame($backChannel, $members['backchannel_logout_supported']);
        static::assertSame($backChannel, $members['backchannel_logout_session_supported']);
        static::assertSame($frontChannel, $members['frontchannel_logout_supported']);
        static::assertSame($frontChannel, $members['frontchannel_logout_session_supported']);
    }

    /**
     * @return iterable<string, array{ServedLogoutChannelsInterface, bool, bool}>
     */
    public static function provideServedChannels(): iterable
    {
        yield 'both wired' => [ServedChannels::both(), true, true];
        yield 'the back channel alone' => [ServedChannels::backChannelOnly(), true, false];
        yield 'the front channel alone' => [ServedChannels::frontChannelOnly(), false, true];
        yield 'a deployment that tells nobody' => [ServedChannels::none(), false, false];
    }
}
