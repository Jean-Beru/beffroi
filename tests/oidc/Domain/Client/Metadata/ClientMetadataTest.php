<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client\Metadata;

use Heidi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Heidi\Oidc\Domain\Client\Metadata\DeclaredMembers;
use Heidi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Heidi\Oidc\Domain\Client\Metadata\SpecifiedDefaults;
use Heidi\Oidc\Exception\LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7591 §2, §3.1.1: the metadata of a registration is read from an ordered set of sources, the first that
 * carries a member being the one that answers for it. It is what makes a source something added in front of
 * another rather than a branch in the reader (issue #335).
 */
final class ClientMetadataTest extends TestCase
{
    #[Test]
    public function theFirstSourceThatCarriesAMemberAnswersForIt(): void
    {
        // Given
        $metadata = new ClientMetadata([
            new RegisteredMembers([
                'client_name' => 'What the statement says',
            ]),
            new DeclaredMembers([
                'client_name' => 'What the body says',
            ]),
        ]);

        // When / Then
        static::assertSame('What the statement says', $metadata->value('client_name'));
    }

    #[Test]
    public function aMemberNoSourceCarriesIsCarriedByNobody(): void
    {
        // Given
        $metadata = new ClientMetadata([new RegisteredMembers([])]);

        // When / Then
        static::assertFalse($metadata->has('logo_uri'));
    }

    #[Test]
    public function aMemberNoSourceCarriesHasNoValue(): void
    {
        // Given
        $metadata = new ClientMetadata([new RegisteredMembers([])]);

        // When / Then
        static::assertNull($metadata->value('logo_uri'));
    }

    /**
     * A configuration tree fills every option nobody wrote with null, and a body that sends a member as JSON
     * null says nothing about it: either way the source behind it answers.
     */
    #[Test]
    public function aMemberASourceCarriesAsNullIsAMemberItDoesNotCarry(): void
    {
        // Given
        $metadata = new ClientMetadata([
            new DeclaredMembers([
                'token_endpoint_auth_method' => null,
            ]),
            new SpecifiedDefaults(),
        ]);

        // When / Then
        static::assertSame('client_secret_basic', $metadata->value('token_endpoint_auth_method'));
    }

    #[Test]
    public function itSaysWhichSourceAValueCameFrom(): void
    {
        // Given
        $metadata = new ClientMetadata([new RegisteredMembers(['grant_types' => ['refresh_token']]), new SpecifiedDefaults()]);

        // When / Then
        static::assertSame('the registration the client sent', $metadata->sourceOf('grant_types'));
    }

    #[Test]
    public function itSaysTheSourceOfAValueNobodyCarriedIsNobody(): void
    {
        // Given
        $metadata = new ClientMetadata([new RegisteredMembers([])]);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('No source of this registration carries a "logo_uri".');

        // When
        $metadata->sourceOf('logo_uri');
    }

    /**
     * What the reader checks its own names against: a member nobody reads is refused wherever it was
     * written, so every source is asked.
     */
    #[Test]
    public function everyMemberAnySourceCarriesIsNamedOnce(): void
    {
        // Given
        $metadata = new ClientMetadata([
            new RegisteredMembers([
                'grant_types' => ['authorization_code'],
                'invented' => 'x',
            ]),
            new SpecifiedDefaults(),
        ]);

        // When / Then
        static::assertSame(['grant_types', 'invented', 'token_endpoint_auth_method'], $metadata->members());
    }
}
