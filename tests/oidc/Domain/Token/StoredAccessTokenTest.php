<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\OpaqueTokenValue;
use Heidi\Oidc\Domain\Token\StoredAccessToken;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class StoredAccessTokenTest extends TestCase
{
    private AuthenticationSession $session;

    private Client $client;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
    }

    /**
     * Architecture §4.6: everything a resource or the introspection endpoint answers with, kept instead
     * of written as claims, with the authentication of the original authorization.
     */
    #[Test]
    public function itRecordsWhatAJwtWouldCarryAsClaims(): void
    {
        // Given
        $issuedAt = Fixtures::now()->modify('+5 minutes');
        $this->session->recordProof(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), Fixtures::context($issuedAt));
        $claims = new ClaimsRequest([
            'email' => new ClaimRequest(true),
        ]);
        $grant = Uuid::v7();

        // When
        $token = Tokens::storedAccessToken('the-token', $this->client, $this->session, $issuedAt, $grant, ['openid', 'profile'], $claims);

        // Then
        static::assertSame(OpaqueTokenValue::hash('the-token'), $token->tokenHash);
        static::assertSame($grant, $token->grantId);
        static::assertSame($this->client, $token->client);
        static::assertSame($this->client->clientId, $token->clientId);
        static::assertSame($this->client->tenant, $token->tenant);
        static::assertSame($this->session, $token->session);
        static::assertEquals([new Scope('openid'), new Scope('profile')], $token->scopes);
        static::assertSame($claims, $token->claimsRequest);
        static::assertEquals($issuedAt, $token->authenticatedAt);
        static::assertSame(['pwd', 'otp'], $token->authenticationMethods);
        static::assertSame('2', $token->authenticationContextClass);
        static::assertEquals($issuedAt, $token->issuedAt);
        static::assertEquals($issuedAt->modify('+10 minutes'), $token->expiresAt);
    }

    /**
     * The record of a response: the scopes of that response, not the ones granted, and the grant the
     * tokens descend from.
     */
    #[Test]
    public function itIsBuiltFromAnAuthorizationWithTheScopesOfTheResponse(): void
    {
        // Given
        $code = Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), ['openid', 'email']);
        $authorization = GrantedAuthorization::fromRefreshToken(Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), Tokens::family(Fixtures::now(), grantId: $code->grantId), ['openid', 'email']), [new Scope('email')]);

        // When
        $token = StoredAccessToken::fromAuthorization(OpaqueTokenValue::hash('the-token'), $authorization, Fixtures::now(), Fixtures::now()->modify('+10 minutes'));

        // Then
        static::assertEquals([new Scope('email')], $token->scopes);
        static::assertTrue($code->grantId->equals($token->grantId));
        static::assertSame($this->session, $token->session);
        static::assertEquals($this->session->authenticatedAt(), $token->authenticatedAt);
    }

    #[Test]
    public function itExpiresAtTheSecondOfItsExpiry(): void
    {
        // Given
        $token = Tokens::storedAccessToken('the-token', $this->client, $this->session, Fixtures::now());

        // When / Then
        static::assertFalse($token->isExpired(Fixtures::now()->modify('+9 minutes 59 seconds')));
        static::assertTrue($token->isExpired(Fixtures::now()->modify('+10 minutes')));
    }

    #[Test]
    public function itKnowsItsScopes(): void
    {
        // Given
        $token = Tokens::storedAccessToken('the-token', $this->client, $this->session, Fixtures::now(), scopes: ['openid', 'email']);

        // When / Then
        static::assertTrue($token->hasScope(new Scope('email')));
        static::assertFalse($token->hasScope(new Scope('profile')));
    }

    #[Test]
    public function itRefusesAValueThatIsNotAHexSha256(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->token(tokenHash: OpaqueTokenValue::draw());
    }

    #[Test]
    public function itRefusesASessionOfAnotherTenant(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->token(client: Clients::public(Fixtures::tenant('other', 'https://id.other.example')));
    }

    #[Test]
    public function itRefusesAnEmptyScopeList(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->token(scopes: []);
    }

    /**
     * RFC 8176: a session always has at least one proof, so a token always has at least one method.
     */
    #[Test]
    public function itRefusesAnEmptyMethodList(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->token(methods: []);
    }

    #[Test]
    public function itRefusesToExpireBeforeItWasIssued(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->token(expiresAt: Fixtures::now());
    }

    /**
     * @param list<Scope>|null $scopes
     * @param list<string>|null $methods
     */
    private function token(?string $tokenHash = null, ?Client $client = null, ?array $scopes = null, ?array $methods = null, ?DateTimeImmutable $expiresAt = null): StoredAccessToken
    {
        return new StoredAccessToken(
            $tokenHash ?? OpaqueTokenValue::hash('the-token'),
            Uuid::v7(),
            $client ?? $this->client,
            $this->session,
            $scopes ?? [Scope::openid()],
            null,
            Fixtures::now(),
            $methods ?? ['pwd'],
            '1',
            Fixtures::now(),
            $expiresAt ?? Fixtures::now()->modify('+10 minutes'),
        );
    }
}
