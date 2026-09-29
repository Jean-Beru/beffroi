<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client\Metadata;

use Heidi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Heidi\Oidc\Exception\InvalidClientMetadataException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Decision 0009: a client that registers itself gets nothing a declared client does not get, and the
 * members this provider defines for itself are what a deployment writes or what the registration policy
 * of a tenant grants (decision 0017). A client that sends one is refused rather than obeyed.
 */
final class RegisteredMembersTest extends TestCase
{
    #[Test]
    #[DataProvider('provideMembersOfTheDeployment')]
    public function aClientDoesNotRegisterAMemberOfTheDeployment(string $member, mixed $value): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The member "%s" is not one a client registers: it is written by whoever declares a client or by the registration policy of the tenant, and never asked for (decision 0009).',
            $member,
        ));

        // When
        new RegisteredMembers([
            'redirect_uris' => ['https://rp.example/cb'],
            $member => $value,
        ]);
    }

    /**
     * @return iterable<string, array{string, mixed}>
     */
    public static function provideMembersOfTheDeployment(): iterable
    {
        yield 'the consent exemption of architecture section 7' => ['requires_consent', false];

        yield 'the PKCE exemption of decision 0008' => ['requires_pkce', false];

        yield 'the shape of its access tokens' => ['access_token_format', 'opaque'];

        yield 'the resources it may ask a token for' => ['resources', ['https://api.example/']];

        yield 'what it may exchange a token for' => ['token_exchange', []];

        yield 'who may act for the subject of its tokens' => ['may_act', []];

        yield 'the binding it is held to' => ['require_sender_constrained_tokens', true];
    }

    /**
     * A member of RFC 7591 §2 is one a client registers, however much it grants: what it may register it
     * to is held to what its tenant offers, where a registration meets that tenant.
     */
    #[Test]
    public function aClientRegistersTheMembersOfTheSpecifications(): void
    {
        // Given
        $members = [
            'redirect_uris' => ['https://rp.example/cb'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'scope' => 'openid profile',
        ];

        // When
        $source = new RegisteredMembers($members);

        // Then
        static::assertSame($members, $source->members());
    }

    /**
     * A member sent as JSON null is a member the client said nothing about, and it is not one it sent.
     */
    #[Test]
    public function aMemberOfTheDeploymentSentAsNullIsStillOneTheClientSent(): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);

        // When
        new RegisteredMembers([
            'requires_pkce' => null,
        ]);
    }
}
