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
 * RFC 7591 §2.3
 */
final class AttestedMembersTest extends TestCase
{
    /**
     * RFC 7591 §2.3
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
     * RFC 7519 §4.1
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
     * Decision 0009
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

    #[Test]
    public function itSaysWhereItsMembersCameFrom(): void
    {
        // When / Then
        static::assertSame('the software statement its issuer signed', new AttestedMembers([])->source());
    }
}
