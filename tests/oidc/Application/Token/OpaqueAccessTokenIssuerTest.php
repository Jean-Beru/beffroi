<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use DateInterval;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Token\CertificateConfirmation;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Tests\Fixture\Certificates;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;

final class OpaqueAccessTokenIssuerTest extends TestCase
{
    private AuthenticationSession $session;

    private Client $client;

    private InMemoryAccessTokenRepository $tokens;

    private OpaqueAccessTokenIssuer $issuer;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
        $this->tokens = new InMemoryAccessTokenRepository();
        $this->issuer = new OpaqueAccessTokenIssuer($this->tokens);
    }

    /**
     * Architecture §4.6: ten minutes from issuance, as the value the repository drew, kept under its hash
     * with what the authorization says.
     */
    #[Test]
    public function itMintsAnOpaqueValueForTenMinutesAndKeepsItsRecord(): void
    {
        // Given
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
            ['openid', 'email'],
        ));

        // When
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now(), $token->issuedAt);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $token->expiresAt);
        static::assertSame(1, preg_match('/^[A-Za-z0-9_-]{43}$/', $token->value));
        $record = $this->tokens->find($token->value) ?? static::fail('The record was kept.');
        static::assertSame($this->client, $record->client);
        static::assertTrue($authorization->grantId->equals($record->grantId));
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $record->expiresAt);
    }

    /**
     * RFC 8705 §3: an opaque token is bound the way a self-contained one is, its record carrying what
     * the token would have carried as a claim; the resource server reads it back by introspection
     * (§3.2).
     */
    #[Test]
    public function itBindsTheRecordToWhatTheClientProved(): void
    {
        // Given
        $certificate = Certificates::client();
        $authorization = GrantedAuthorization::fromAuthorizationCode(
            Tokens::code('the-code', $this->client, $this->session, Fixtures::now()),
            CertificateConfirmation::ofCertificate($certificate),
        );

        // When
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // Then
        $record = $this->tokens->find($token->value) ?? static::fail('The record was kept.');
        static::assertEquals(CertificateConfirmation::ofCertificate($certificate), $record->confirmation);
    }

    #[Test]
    public function theLifetimeIsConfigurable(): void
    {
        // Given
        $issuer = new OpaqueAccessTokenIssuer($this->tokens, new DateInterval('PT1H'));
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now()));

        // When
        $token = $issuer->issue($authorization, Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now()->modify('+1 hour'), $token->expiresAt);
        static::assertEquals(Fixtures::now()->modify('+1 hour'), $this->tokens->all()[0]->expiresAt);
    }
}
