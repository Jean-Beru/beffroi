<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Requests;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function strlen;

final class AuthorizationCodeTest extends TestCase
{
    private AuthenticationSession $session;

    private Client $client;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
    }

    /**
     * Architecture §4.4: the code is 256 bits of the CSPRNG in base64url and is stored as its SHA-256.
     */
    #[Test]
    public function aCodeIsRandomAndStoredHashed(): void
    {
        $code = AuthorizationCode::generate();
        $again = AuthorizationCode::generate();

        static::assertSame(1, preg_match('/^[A-Za-z0-9_-]{43}$/', $code));
        static::assertNotSame($code, $again);
        static::assertSame(64, strlen(AuthorizationCode::hash($code)));
        static::assertSame(AuthorizationCode::hash($code), AuthorizationCode::hash($code));
        static::assertNotSame(AuthorizationCode::hash($code), AuthorizationCode::hash($again));
        static::assertSame('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', AuthorizationCode::hash(''));
    }

    /**
     * Architecture §4.4: everything the token endpoint needs, with the authentication as it was when
     * the code was issued.
     */
    #[Test]
    public function itRecordsWhatTheGrantWillNeed(): void
    {
        $issuedAt = Fixtures::now()->modify('+5 minutes');
        $this->session->recordProof(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), Fixtures::context($issuedAt));

        $code = $this->code($issuedAt, $issuedAt->modify('+60 seconds'));

        static::assertSame('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', $code->codeHash);
        static::assertSame($this->client, $code->client);
        static::assertSame($this->session, $code->session);
        static::assertSame('https://spa.example/callback', (string) $code->redirectUri);
        static::assertEquals([new Scope('openid')], $code->scopes);
        static::assertSame('n-0S6_WzA2Mj', $code->nonce);
        static::assertSame(Requests::CHALLENGE, $code->codeChallenge->value);
        static::assertNull($code->claimsRequest);
        static::assertEquals($issuedAt, $code->authenticatedAt);
        static::assertSame(['pwd', 'otp'], $code->authenticationMethods);
        static::assertNull($code->authenticationContextClass);
        static::assertEquals($issuedAt, $code->issuedAt);
        static::assertEquals($issuedAt->modify('+60 seconds'), $code->expiresAt);
    }

    #[Test]
    public function itRefusesAValueThatIsNotAHexSha256(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->code(Fixtures::now(), Fixtures::now()->modify('+60 seconds'), codeHash: AuthorizationCode::generate());
    }

    #[Test]
    public function itRefusesASessionOfAnotherTenant(): void
    {
        $client = Clients::public(Fixtures::tenant('other', 'https://id.other.example'));

        $this->expectException(InvalidArgumentException::class);
        new AuthorizationCode(AuthorizationCode::hash(''), $client, $this->session, $client->redirectUris[0], [new Scope('openid')], null, new CodeChallenge(Requests::CHALLENGE, CodeChallengeMethod::S256), null, Fixtures::now(), ['pwd'], null, Fixtures::now(), Fixtures::now()->modify('+60 seconds'));
    }

    #[Test]
    public function itRefusesAnEmptyScopeList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->code(Fixtures::now(), Fixtures::now()->modify('+60 seconds'), scopes: []);
    }

    /**
     * RFC 8176: a session always has at least one proof, so a code always has at least one method.
     */
    #[Test]
    public function itRefusesAnEmptyMethodList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new AuthorizationCode(AuthorizationCode::hash(''), $this->client, $this->session, $this->client->redirectUris[0], [new Scope('openid')], null, new CodeChallenge(Requests::CHALLENGE, CodeChallengeMethod::S256), null, Fixtures::now(), [], null, Fixtures::now(), Fixtures::now()->modify('+60 seconds'));
    }

    #[Test]
    public function itRefusesToExpireBeforeItWasIssued(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->code(Fixtures::now(), Fixtures::now());
    }

    /**
     * @param list<Scope> $scopes
     */
    private function code(DateTimeImmutable $issuedAt, DateTimeImmutable $expiresAt, string $codeHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', array $scopes = [new Scope('openid')]): AuthorizationCode
    {
        return new AuthorizationCode(
            $codeHash,
            $this->client,
            $this->session,
            $this->client->redirectUris[0],
            $scopes,
            'n-0S6_WzA2Mj',
            new CodeChallenge(Requests::CHALLENGE, CodeChallengeMethod::S256),
            null,
            $this->session->authenticatedAt(),
            $this->session->methodReferences(),
            $this->session->authenticationContextClass,
            $issuedAt,
            $expiresAt,
        );
    }
}
