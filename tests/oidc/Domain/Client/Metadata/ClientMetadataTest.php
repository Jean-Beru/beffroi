<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client\Metadata;

use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Beffroi\Oidc\Domain\Client\Metadata\DeclaredMembers;
use Beffroi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Beffroi\Oidc\Domain\Client\Metadata\SpecifiedDefaults;
use Beffroi\Oidc\Exception\LogicException;
use function array_fill_keys;
use function array_map;
use function hrtime;
use function range;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7591 §2, §3.1.1
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

    #[Test]
    public function fiftyThousandMembersOfTwoSourcesAreNamedInLessThanASecond(): void
    {
        // Given
        $names = array_map(static fn (int $index): string => 'member_' . $index, range(1, 50_000));
        $metadata = new ClientMetadata([
            new RegisteredMembers(array_fill_keys($names, 'statement')),
            new DeclaredMembers(array_fill_keys($names, 'body')),
        ]);

        // When
        $start = hrtime(true);
        $members = $metadata->members();
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertSame($names, $members);
        static::assertLessThan(1_000, $milliseconds);
    }
}
