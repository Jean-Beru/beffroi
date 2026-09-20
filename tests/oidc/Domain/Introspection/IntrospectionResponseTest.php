<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Introspection;

use DateTimeImmutable;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Introspection\IntrospectionResponse;
use Heidi\Oidc\Domain\Scope\Scope;
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
        static::assertSame([
            'active' => false,
        ], $response->members);
        static::assertSame('{"active":false}', $response->body());
        static::assertSame('application/json', $response->contentType());
        static::assertNull($response->jwt);
    }

    /**
     * RFC 7662 §2.2: the members in the order of the section, then the authentication of RFC 9068 §2.2.1
     * and the two names of the provider (architecture §4.6); "aud" and "client_id" are the client until a
     * "resource" parameter says otherwise.
     */
    #[Test]
    public function anActiveTokenIsDescribedByWhatTheProviderKnows(): void
    {
        // Given
        $session = Uuid::v7();
        $grant = Uuid::v7();
        $token = new VerifiedAccessToken(Clients::public(Fixtures::tenant()), new Subject('alice-subject'), $session, $grant, [Scope::openid(), new Scope('email')], ['name'], new AuthenticationSnapshot(new DateTimeImmutable('@1789466000'), ['pwd', 'otp'], '2'), new DateTimeImmutable('@1789466400'), new DateTimeImmutable('@1789467000'));

        // When
        $response = IntrospectionResponse::active($token, new Issuer('https://id.acme.example'));

        // Then
        static::assertTrue($response->isActive());
        static::assertSame([
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
        ], $response->members);
        static::assertStringStartsWith('{"active":true,"scope":"openid email","client_id":"spa","token_type":"Bearer","exp":1789467000,"iat":1789466400,', $response->body());
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
