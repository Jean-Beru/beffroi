<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use DateInterval;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Tokens;
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
        $this->issuer = new OpaqueAccessTokenIssuer($this->tokens, Secrets::drawer());
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function itMintsAnOpaqueValueForTenMinutesAndKeepsItsRecord(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
            ['openid', 'email'],
        ));

        // When
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

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
     * RFC 8705 §3, §3.2
     */
    #[Test]
    public function itBindsTheRecordToWhatTheClientProved(): void
    {
        // Given
        $certificate = Certificates::client();
        $authorization = UserAuthorization::fromAuthorizationCode(
            Grants::authorizationCode(),
            Tokens::code('the-code', $this->client, $this->session, Fixtures::now()),
            CertificateConfirmation::ofCertificate($certificate),
        );

        // When
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // Then
        $record = $this->tokens->find($token->value) ?? static::fail('The record was kept.');
        static::assertEquals(CertificateConfirmation::ofCertificate($certificate), $record->confirmation);
    }

    #[Test]
    public function theLifetimeIsConfigurable(): void
    {
        // Given
        $issuer = new OpaqueAccessTokenIssuer($this->tokens, Secrets::drawer(), new DateInterval('PT1H'));
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));

        // When
        $token = Tokens::accessToken($issuer, $authorization, Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now()->modify('+1 hour'), $token->expiresAt);
        static::assertEquals(Fixtures::now()->modify('+1 hour'), $this->tokens->all()[0]->expiresAt);
    }
}
