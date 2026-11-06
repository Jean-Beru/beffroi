<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client\Metadata;

use function array_diff;
use Beffroi\Oidc\Domain\Client\Metadata\GrantedMembers;
use Beffroi\Oidc\Domain\Client\Metadata\MembersOfTheDeployment;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Decision 0043
 */
final class GrantedMembersTest extends TestCase
{
    #[Test]
    public function aTokenGivesTheMembersOfTheDeploymentItMayGive(): void
    {
        // Given
        $members = [
            'resources' => ['https://api.example/'],
            'access_token_format' => 'opaque',
            'require_sender_constrained_tokens' => true,
            'token_exchange' => [
                'subject_token_types' => ['urn:ietf:params:oauth:token-type:access_token'],
            ],
            'may_act' => 'a-gateway',
        ];

        // When
        $source = new GrantedMembers($members);

        // Then
        static::assertSame($members, $source->members());
    }

    #[Test]
    public function everyMemberATokenGivesIsAMemberOfTheDeployment(): void
    {
        // When / Then
        static::assertSame([], array_diff(GrantedMembers::NAMES, MembersOfTheDeployment::NAMES));
    }

    /**
     * Decision 0017
     */
    #[Test]
    #[DataProvider('provideMembersNoTokenGives')]
    public function aTokenGivesNothingElse(string $member, mixed $value): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The member "%s" is not one an initial access token gives: a token gives the clients it registers resources, access_token_format, require_sender_constrained_tokens, token_exchange and may_act, and nothing else (decision 0043).',
            $member,
        ));

        // When
        new GrantedMembers([
            'resources' => ['https://api.example/'],
            $member => $value,
        ]);
    }

    /**
     * @return iterable<string, array{string, mixed}>
     */
    public static function provideMembersNoTokenGives(): iterable
    {
        yield 'the consent of the people it signs in' => ['requires_consent', false];

        yield 'the PKCE exemption of decision 0017' => ['requires_pkce', false];

        yield 'a member the client registers itself' => ['redirect_uris', ['https://rp.example/cb']];
    }

    #[Test]
    public function itIsTheSourceTheTenantIssued(): void
    {
        // When / Then
        static::assertSame('the initial access token the tenant issued', new GrantedMembers([])->source());
    }

    #[Test]
    public function itReadsBackTheDocumentItWrote(): void
    {
        // Given
        $source = new GrantedMembers([
            'resources' => ['https://api.example/'],
            'require_sender_constrained_tokens' => true,
        ]);

        // When
        $read = GrantedMembers::fromDocument($source->toDocument());

        // Then
        static::assertSame($source->members(), $read->members());
    }

    #[Test]
    public function aDocumentWhoseMembersAreNotNamedIsRefused(): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIs('The member "0" is not one an initial access token gives: a token gives the clients it registers resources, access_token_format, require_sender_constrained_tokens, token_exchange and may_act, and nothing else (decision 0043).');

        // When
        GrantedMembers::fromDocument(['https://api.example/']);
    }
}
