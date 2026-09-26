<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedResponses;
use Heidi\Oidc\Tests\Fixture\ServedModes;
use Heidi\Oidc\Tests\Fixture\WiredModes;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8414 §2: the provider answers an authorization request with a code, in the modes the integration
 * wired and no other (issue #98).
 */
final class AnnouncedResponsesTest extends TestCase
{
    #[Test]
    public function theyAreTheModesTheIntegrationWired(): void
    {
        // Given
        $announced = new AnnouncedResponses(ServedModes::queryAndFormPost());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'response_types_supported' => ['code'],
                'response_modes_supported' => ['query', 'form_post'],
            ],
            $members,
        );
    }

    /**
     * A deployment that wired no way of posting a response announces the one it delivers in and nothing
     * else: the document follows the endpoint, never an enumeration of the module.
     */
    #[Test]
    public function aProviderThatPostsNoResponseAnnouncesTheDefaultModeAlone(): void
    {
        // Given
        $announced = new AnnouncedResponses(ServedModes::queryOnly());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['query'], $members['response_modes_supported']);
    }

    /**
     * RFC 8414 §2: a mode wired twice is announced once.
     */
    #[Test]
    public function aModeWiredTwiceIsAnnouncedOnce(): void
    {
        // Given
        $announced = new AnnouncedResponses(WiredModes::of([ServedModes::FORM_POST, ServedModes::QUERY, ServedModes::FORM_POST]));

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['form_post', 'query'], $members['response_modes_supported']);
    }

    /**
     * JARM §2.1 and issue #98: "jwt" is announced because a mode that signs the answer is wired, and it
     * comes last, after the modes that deliver.
     */
    #[Test]
    public function aWiredSignedModeAnnouncesTheAlias(): void
    {
        // Given
        $announced = new AnnouncedResponses(WiredModes::of(
            [ServedModes::QUERY, ServedModes::SIGNED_QUERY],
            [ServedModes::SIGNED_QUERY],
            ServedModes::SIGNED_QUERY,
        ));

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['query', 'query.jwt', 'jwt'], $members['response_modes_supported']);
    }

    #[Test]
    public function aDeploymentWithoutASignedModeAnnouncesNoAlias(): void
    {
        // Given
        $announced = new AnnouncedResponses(ServedModes::queryAndFormPost());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['query', 'form_post'], $members['response_modes_supported']);
    }
}
