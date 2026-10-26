<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client\Metadata;

use Beffroi\Oidc\Domain\Client\Metadata\AttestedMembers;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\DataProviderExternal;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * RFC 7591 §2.3: what a verified statement carries as client metadata, which is its claims minus the ones
 * it carries about itself, held to what a client registers.
 */
final class AttestedMembersTest extends TestCase
{
    /**
     * §2.3: "whose claims are client metadata values about the client software".
     */
    #[Test]
    public function itCarriesTheClaimsThatDescribeTheClient(): void
    {
        // Given
        $members = new AttestedMembers([
            'iss' => 'https://store.example.com',
            'client_name' => 'Invoice reader, attested',
            'software_id' => 'invoice-reader',
        ]);

        // When / Then
        static::assertSame(
            [
                'client_name' => 'Invoice reader, attested',
                'software_id' => 'invoice-reader',
            ],
            $members->members(),
        );
    }

    /**
     * RFC 7519 §4.1: a claim a statement carries about itself describes no client, and it is dropped here
     * rather than refused by the reader, a statement of the ordinary shape being no registration with
     * unknown keys.
     */
    #[Test]
    #[DataProvider('provideClaimsAboutTheStatement')]
    public function itCarriesNothingAStatementSaysAboutItself(string $claim): void
    {
        // Given
        $members = new AttestedMembers([
            $claim => 'whatever it says',
            'client_name' => 'Invoice reader, attested',
        ]);

        // When / Then
        static::assertArrayNotHasKey($claim, $members->members());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideClaimsAboutTheStatement(): iterable
    {
        foreach (['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'] as $claim) {
            yield $claim => [$claim];
        }
    }

    /**
     * Decision 0009: what a statement says is what the client is, never what it may have. The members of this
     * provider alone are held to the same list whether the client sent them or an authority signed them, or
     * the client would be registered with one and read back from its row as no client at all.
     */
    #[Test]
    #[DataProviderExternal(RegisteredMembersTest::class, 'provideMembersOfTheDeployment')]
    public function aStatementDoesNotCarryAMemberOfTheDeployment(string $member, mixed $value): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The member "%s" is not one a client registers: it is written by whoever declares a client or by the registration policy of the tenant, and never asked for (decision 0009).',
            $member,
        ));

        // When
        new AttestedMembers([
            'iss' => 'https://store.example.com',
            'client_name' => 'Invoice reader, attested',
            $member => $value,
        ]);
    }

    /**
     * The refusal says where the member came from, the statement and not what the client typed beside it.
     */
    #[Test]
    public function itsRefusalOfAMemberOfTheDeploymentNamesTheStatement(): void
    {
        // When
        try {
            new AttestedMembers([
                'requires_consent' => false,
            ]);
            static::fail('A statement carrying a member of the deployment should have been refused.');
        } catch (InvalidClientMetadataException $exception) {
            // Then
            static::assertSame('requires_consent', $exception->member);
            static::assertSame('the software statement its issuer signed', $exception->source);
        }
    }

    /**
     * What a refusal names it by, so that a member that does not hold says where the value came from.
     */
    #[Test]
    public function itSaysWhereItsMembersCameFrom(): void
    {
        // When / Then
        static::assertSame('the software statement its issuer signed', new AttestedMembers([])->source());
    }
}
