<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedBackchannelAuthentication;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Tests\Fixture\DeliveryModes;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * CIBA Core §4: where a client starts a request for a user it names, the ways it may be told the request
 * was answered, and what this provider does not take.
 */
final class AnnouncedBackchannelAuthenticationTest extends TestCase
{
    #[Test]
    public function itNamesTheEndpointTheModesAndWhatSignsARequest(): void
    {
        // Given
        $announced = $this->announced();

        // When
        $members = $announced->metadata(Fixtures::tenant('acme', 'https://as.example/acme'));

        // Then
        static::assertSame('https://as.example/acme/backchannel_authentication', $members['backchannel_authentication_endpoint']);
        static::assertSame(['poll', 'ping'], $members['backchannel_token_delivery_modes_supported']);
        static::assertSame(
            $this->algorithms()->signing(),
            $members['backchannel_authentication_request_signing_alg_values_supported'],
        );
    }

    /**
     * §7.1: this provider does not take a user code, and says so rather than leaving a client to find out.
     */
    #[Test]
    public function itSaysThatItTakesNoUserCode(): void
    {
        // When
        $members = $this->announced()->metadata(Fixtures::tenant());

        // Then
        static::assertFalse($members['backchannel_user_code_parameter_supported']);
    }

    /**
     * A contributor announces nothing rather than an endpoint nothing serves: a provider wired with no
     * grant of this flow says nothing of it.
     */
    #[Test]
    public function aProviderWiredWithNoSuchGrantAnnouncesNothing(): void
    {
        // Given
        $announced = new AnnouncedBackchannelAuthentication(
            new Endpoints(),
            Grants::served(),
            DeliveryModes::served(),
            $this->algorithms(),
        );

        // When / Then
        static::assertSame([], $announced->metadata(Fixtures::tenant()));
    }

    private function announced(): AnnouncedBackchannelAuthentication
    {
        return new AnnouncedBackchannelAuthentication(
            new Endpoints(),
            Grants::servedWithCiba(),
            DeliveryModes::served(),
            $this->algorithms(),
        );
    }

    private function algorithms(): AnnouncedAlgorithms
    {
        return new AnnouncedAlgorithms(Algorithms::all(), Algorithms::keyEncryption(), Algorithms::contentEncryption());
    }
}
