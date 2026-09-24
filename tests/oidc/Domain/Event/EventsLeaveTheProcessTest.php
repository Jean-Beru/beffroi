<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Event;

use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Event\AuthorizationCodeIssued;
use Heidi\Oidc\Domain\Event\AuthorizationCodeReplayed;
use Heidi\Oidc\Domain\Event\ConsentGranted;
use Heidi\Oidc\Domain\Event\LogoutTokenIssued;
use Heidi\Oidc\Domain\Event\RefreshTokenReuseDetected;
use Heidi\Oidc\Domain\Event\RefreshTokenRotated;
use Heidi\Oidc\Domain\Event\TokenRevoked;
use Heidi\Oidc\Domain\Event\TokensIssued;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Methods;
use Heidi\Oidc\Tests\Fixture\Tokens;
use Heidi\Oidc\Tests\Fixture\UnserializableClientJwksFetcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function serialize;
use Symfony\Component\Uid\Uuid;
use function unserialize;

/**
 * Architecture §5.6: the events of the provider are handled asynchronously, so every one of them is
 * written to a queue. A client carries the method that authenticates it, and a method that proves a key
 * or a certificate carries the reader of the "jwks_uri" of the client, which is an HTTP client of the
 * framework: an event that carried a client could not be written at all, and would carry the
 * configuration of that HTTP client to the broker if it could. So an event carries what happened, by
 * identifier, and never the client itself.
 *
 * The client of each case authenticates with "private_key_jwt" and reads its keys through something that
 * cannot be serialized, which is what a deployment has.
 */
final class EventsLeaveTheProcessTest extends TestCase
{
    /**
     * @return iterable<string, array{DomainEventInterface}>
     */
    public static function events(): iterable
    {
        $session = Fixtures::session();
        $client = self::client($session);
        $now = Fixtures::now();
        $code = Tokens::code('the-code', $client, $session, $now);
        $family = Tokens::family($now);
        $previous = Tokens::refreshToken('previous', $client, $session, $now, $family);
        $next = Tokens::refreshToken('next', $client, $session, $now, $family);
        $accessToken = Tokens::storedAccessToken('opaque', $client, $session, $now);
        $context = Fixtures::context();

        yield 'an authorization code issued' => [AuthorizationCodeIssued::of($code, $context)];
        yield 'an authorization code replayed' => [AuthorizationCodeReplayed::of($now, $code, $client, [$previous], $context)];
        yield 'a consent granted' => [ConsentGranted::of(
            new Consent(Uuid::v7(), $session->user, $client, new Scopes([Scope::openid()]), $now),
            null,
            $context,
        )];
        yield 'a logout token issued' => [LogoutTokenIssued::of(
            $client,
            new ClientUri('https://key.example/backchannel-logout'),
            $session,
            'eyJ.the.token',
            $now,
            $context,
        )];
        yield 'a refresh token rotated' => [RefreshTokenRotated::of($previous, $next, $context)];
        yield 'a refresh token reused' => [RefreshTokenReuseDetected::of($now, $previous, [$previous, $next], $context)];
        yield 'an access token revoked' => [TokenRevoked::ofAccessToken($now, $accessToken, $client, $context)];
        yield 'a refresh token revoked' => [TokenRevoked::ofRefreshToken($now, $previous, $client, [$accessToken], $context)];
        yield 'the tokens of a grant issued' => [TokensIssued::of(
            $now,
            GrantedAuthorization::fromAuthorizationCode($code),
            $now->modify('+10 minutes'),
            true,
            $next,
            $context,
        )];
    }

    #[Test]
    #[DataProvider('events')]
    public function anEventIsWrittenToTheQueueAndReadBack(DomainEventInterface $event): void
    {
        // When
        $written = serialize($event);

        // Then
        static::assertInstanceOf($event::class, unserialize($written));
    }

    /**
     * A client whose method cannot be serialized, as the one of a deployment cannot.
     */
    private static function client(AuthenticationSession $session): Client
    {
        return Clients::withKeys(
            $session->tenant,
            method: Methods::privateKeyJwt(Methods::keySetProvider(new UnserializableClientJwksFetcher())),
        );
    }
}
