<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client\Metadata;

use Beffroi\Oidc\Domain\Client\Metadata\AttestedMembers;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7591 §2.3: what a verified statement carries as client metadata, which is its claims minus the ones
 * it carries about itself.
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
     * What a refusal names it by, so that a member that does not hold says where the value came from.
     */
    #[Test]
    public function itSaysWhereItsMembersCameFrom(): void
    {
        // When / Then
        static::assertSame('the software statement its issuer signed', new AttestedMembers([])->source());
    }
}
