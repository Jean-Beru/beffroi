<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Introspection;

use DateTimeImmutable;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Exchange\Actor;
use Heidi\Oidc\Domain\Introspection\IntrospectionResponse;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\TokenAudience;
use Heidi\Oidc\Domain\Token\TokenSignIn;
use Heidi\Oidc\Domain\Token\VerifiedAccessToken;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class IntrospectionResponseTest extends TestCase
{
    /**
     * RFC 7662 §2.2: "active" alone, a JSON boolean, when the token is not one to honour.
     */
    #[Test]
    public function anInactiveTokenIsDescribedByActiveFalseAlone(): void
    {
        // When
        $response = IntrospectionResponse::inactive();

        // Then
        static::assertFalse($response->isActive());
        static::assertSame(
            [
                'active' => false,
            ],
            $response->members,
        );
        static::assertSame('{"active":false}', $response->body());
        static::assertSame('application/json', $response->contentType());
        static::assertNull($response->jwt);
    }

    /**
     * RFC 7662 §2.2: the members in the order of the section, then the authentication of RFC 9068 §2.2.1
     * and the two names of the provider (architecture §4.6); "aud" is the client, the token having been
     * asked for no resource, and "client_id" names the client whatever the audience is.
     */
    #[Test]
    public function anActiveTokenIsDescribedByWhatTheProviderKnows(): void
    {
        // Given
        $session = Uuid::v7();
        $grant = Uuid::v7();
        $token = new VerifiedAccessToken(
            Clients::public(Fixtures::tenant()),
            new TokenAudience(['spa']),
            new Subject('alice-subject'),
            $grant,
            new Scopes([Scope::openid(), new Scope('email')]),
            new TokenSignIn($session, new AuthenticationSnapshot(new DateTimeImmutable('@1789466000'), ['pwd', 'otp'], '2')),
            ['name'],
            new DateTimeImmutable('@1789466400'),
            new DateTimeImmutable('@1789467000'),
        );

        // When
        $response = IntrospectionResponse::active($token, new Issuer('https://id.acme.example'));

        // Then
        static::assertTrue($response->isActive());
        static::assertSame(
            [
                'active' => true,
                'scope' => 'openid email',
                'client_id' => 'spa',
                'token_type' => 'Bearer',
                'exp' => 1789467000,
                'iat' => 1789466400,
                'sub' => 'alice-subject',
                'aud' => 'spa',
                'iss' => 'https://id.acme.example',
                'auth_time' => 1789466000,
                'acr' => '2',
                'amr' => ['pwd', 'otp'],
                'sid' => $session->toRfc4122(),
                'grant_id' => $grant->toRfc4122(),
            ],
            $response->members,
        );
        static::assertStringStartsWith(
            '{"active":true,"scope":"openid email","client_id":"spa","token_type":"Bearer","exp":1789467000,"iat":1789466400,',
            $response->body(),
        );
    }

    /**
     * RFC 6749 §4.4, RFC 9068 §2.2: a token a client holds for itself is described by what it says, the
     * client in "sub", and carries no "sid", no "auth_time", no "acr" and no "amr", nobody having signed in
     * for it.
     */
    #[Test]
    public function aTokenNobodySignedInForIsDescribedWithoutASignIn(): void
    {
        // Given
        $grant = Uuid::v7();
        $token = new VerifiedAccessToken(
            Clients::public(Fixtures::tenant(), resources: Clients::resources()),
            new TokenAudience([Clients::CALENDAR]),
            new Subject('spa'),
            $grant,
            new Scopes([new Scope('invoices.read')]),
            null,
            [],
            new DateTimeImmutable('@1789466400'),
            new DateTimeImmutable('@1789467000'),
        );

        // When
        $response = IntrospectionResponse::active($token, new Issuer('https://id.acme.example'));

        // Then
        static::assertSame(
            [
                'active' => true,
                'scope' => 'invoices.read',
                'client_id' => 'spa',
                'token_type' => 'Bearer',
                'exp' => 1789467000,
                'iat' => 1789466400,
                'sub' => 'spa',
                'aud' => Clients::CALENDAR,
                'iss' => 'https://id.acme.example',
                'grant_id' => $grant->toRfc4122(),
            ],
            $response->members,
        );
    }

    /**
     * RFC 8693 §4.1: a token somebody holds for its subject renders who in "act", the most recent actor
     * outermost, which is what a resource server reads to know through whom it was reached.
     */
    #[Test]
    public function aTokenSomebodyHoldsForItsSubjectRendersTheChainOfActors(): void
    {
        // Given
        $grant = Uuid::v7();
        $token = new VerifiedAccessToken(
            Clients::public(Fixtures::tenant(), resources: Clients::resources()),
            new TokenAudience([Clients::CALENDAR]),
            new Subject('alice-subject'),
            $grant,
            new Scopes([new Scope('invoices.read')]),
            null,
            [],
            new DateTimeImmutable('@1789466400'),
            new DateTimeImmutable('@1789467000'),
            null,
            new Actor(new Subject('gateway'), new Actor(new Subject('first-hop'))),
        );

        // When
        $response = IntrospectionResponse::active($token, new Issuer('https://id.acme.example'));

        // Then
        static::assertSame(
            [
                'sub' => 'gateway',
                'act' => [
                    'sub' => 'first-hop',
                ],
            ],
            $response->members['act'],
        );
    }

    /**
     * RFC 8693 §1.3: a token nobody holds for anybody renders no "act" at all, which is what tells an
     * impersonation from a delegation.
     */
    #[Test]
    public function aTokenNobodyHoldsForAnybodyRendersNoActor(): void
    {
        // Given
        $token = new VerifiedAccessToken(
            Clients::public(Fixtures::tenant(), resources: Clients::resources()),
            new TokenAudience([Clients::CALENDAR]),
            new Subject('alice-subject'),
            Uuid::v7(),
            new Scopes([new Scope('invoices.read')]),
            null,
            [],
            new DateTimeImmutable('@1789466400'),
            new DateTimeImmutable('@1789467000'),
        );

        // When
        $response = IntrospectionResponse::active($token, new Issuer('https://id.acme.example'));

        // Then
        static::assertArrayNotHasKey('act', $response->members);
    }

    /**
     * RFC 8707 §2: the audience a resource server reads is the one the token carries, several resources
     * as the list they are (RFC 7519 §4.1.3), while "client_id" goes on naming the client.
     */
    #[Test]
    public function theAudienceIsWhatTheTokenIsAddressedTo(): void
    {
        // Given
        $token = new VerifiedAccessToken(
            Clients::public(Fixtures::tenant(), resources: Clients::resources()),
            new TokenAudience([Clients::CALENDAR, Clients::CONTACTS]),
            new Subject('alice-subject'),
            Uuid::v7(),
            new Scopes([Scope::openid()]),
            new TokenSignIn(Uuid::v7(), new AuthenticationSnapshot(new DateTimeImmutable('@1789466000'), ['pwd'], '1')),
            [],
            new DateTimeImmutable('@1789466400'),
            new DateTimeImmutable('@1789467000'),
        );

        // When
        $response = IntrospectionResponse::active($token, new Issuer('https://id.acme.example'));

        // Then
        static::assertSame([Clients::CALENDAR, Clients::CONTACTS], $response->members['aud']);
        static::assertSame('spa', $response->members['client_id']);
    }

    /**
     * RFC 9701 §5: the signed form travels as the JWT, with its own media type; the members stay.
     */
    #[Test]
    public function aSignedResponseIsTheJwtWithItsMediaType(): void
    {
        // Given
        $response = IntrospectionResponse::inactive();

        // When
        $signed = $response->signed('a.b.c');

        // Then
        static::assertSame('a.b.c', $signed->body());
        static::assertSame('application/token-introspection+jwt', $signed->contentType());
        static::assertSame($response->members, $signed->members);
        static::assertFalse($signed->isActive());
    }

    #[Test]
    public function aSignedResponseIsNotEmpty(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        IntrospectionResponse::inactive()->signed('');
    }
}
