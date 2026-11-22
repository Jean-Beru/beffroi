<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Fixture;

use Beffroi\Tui\Json\Document;
use Beffroi\Tui\Key\SigningKey;
use Beffroi\Tui\Protocol\DpopProofs;
use Beffroi\Tui\Protocol\Identity;
use Beffroi\Tui\Protocol\PrivateKeyJwt;
use Beffroi\Tui\Protocol\ProviderEndpoint;
use Beffroi\Tui\Protocol\TokenResponse;
use Beffroi\Tui\SignIn\AdministratorSession;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\MockClock;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * An administrator's session as a sign-in leaves it, for what is shown of it, what it reads of the administration API
 * and what ending it does: its tokens were obtained at FakeProvider::NOW.
 */
final readonly class Sessions
{
    /**
     * @param array<string, mixed> $tokens the answer of the token endpoint
     * @param string|null $name the name the ID token carries
     * @param ClockInterface|null $clock what the session reads the time on, FakeProvider::NOW when none is given
     */
    public static function of(
        HttpClientInterface $http,
        array $tokens = [],
        ?string $name = null,
        ?Identity $identity = null,
        ?ClockInterface $clock = null,
    ): AdministratorSession {
        $clock ??= new MockClock(new DateTimeImmutable('@' . FakeProvider::NOW));
        $clientKey = SigningKey::generate();
        $proofs = new DpopProofs(SigningKey::generate(), $clock);

        return new AdministratorSession(
            FakeProvider::profile($clientKey),
            FakeProvider::metadata(),
            $identity ?? new Identity('administrator', 'phr', ['hwk', 'user'], FakeProvider::NOW - 10, $name, null),
            TokenResponse::fromDocument(new Document([
                ...[
                    'access_token' => 'the-access-token',
                    'token_type' => 'DPoP',
                    'expires_in' => 300,
                    'scope' => 'openid profile',
                ],
                ...$tokens,
            ])),
            new DateTimeImmutable('@' . FakeProvider::NOW),
            $proofs,
            new ProviderEndpoint($http, new PrivateKeyJwt(FakeProvider::CLIENT_ID, $clientKey, FakeProvider::ISSUER, $clock), $proofs),
            $http,
            $clock,
        );
    }
}
