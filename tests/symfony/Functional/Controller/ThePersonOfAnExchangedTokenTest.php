<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use function http_build_query;
use function rawurlencode;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ActsOfAPersonInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Domain\Event\IntrospectionAnswered;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #601, RFC 8693 §2.2.1 and OIDC Core §8.1: the resources of this provider answer for the person an
 * exchanged token is about, under a pairwise kind as under any other.
 *
 * Two clients and a sector each. The "sub" of the token the first one holds is the name that sector sees its
 * person under, and the record the exchange writes names the client that asked, so looking that "sub" up
 * under the second client finds nobody: what answers is the person the exchange resolved when it read what
 * was presented, kept on the record.
 *
 * The two reads an exchanged token reaches are here. It is addressed to a resource and never to the client
 * that holds it (RFC 8707 §2, RFC 8693 §2.1), so the UserInfo endpoint of this provider refuses it whatever
 * it says of a person, as it refuses every token asked for a resource (ResourceIndicatorFlowTest).
 */
final class ThePersonOfAnExchangedTokenTest extends BrowserTestCase
{
    private const string PERSON_CLIENT_ID = 'exchange-pairwise-app';

    private const string PERSON_SECRET = 'exchange-pairwise-secret-of-at-least-32-c';

    private const string PERSON_REDIRECT_URI = 'https://exchange-sector.test/callback';

    private const string GATEWAY_ID = 'exchange-pairwise-gateway';

    private const string GATEWAY_SECRET = 'exchange-gateway-secret-of-at-least-32-ch';

    private const string CALENDAR = 'https://cal.example.com/';

    private const string ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

    private User $alice;

    protected function setUp(): void
    {
        parent::setUp();
        self::signingKey();
        $this->alice = self::user('alice');
        $this->signIn($this->alice);
    }

    /**
     * RFC 7662 §2.2: the gateway is told what the token it holds is good for, and the "sub" it is described
     * by is the one the token carries, which is the name the first client's sector sees its person under.
     */
    #[Test]
    public function theIntrospectionOfAnExchangedTokenDescribesIt(): void
    {
        // Given
        $presented = $this->tokenOfThePerson();
        $exchanged = $this->exchanged($presented);

        // When
        $described = $this->introspect($exchanged);

        // Then
        static::assertTrue($described['active']);
        static::assertSame(self::subjectOf($presented), $described['sub']);
    }

    /**
     * Issue #589: a read that describes a person is an act of this provider, so the journal of that person
     * holds it. It is the one place the fix shows itself as a row: the answer names nobody when the "sub" of
     * the token is read under the client that asked for it.
     */
    #[Test]
    public function theIntrospectionOfAnExchangedTokenIsInTheJournalOfItsPerson(): void
    {
        // Given
        $exchanged = $this->exchanged($this->tokenOfThePerson());

        // When
        $this->introspect($exchanged);
        self::reload();

        // Then
        static::assertCount(1, self::service('test.beffroi.acts', ActsOfAPersonInterface::class)
            ->lastOf(self::reread($this->alice), [IntrospectionAnswered::NAME], 10));
    }

    /**
     * RFC 8693 §2.1: a token a gateway was given for the subject of another one is itself exchangeable, and
     * what the second exchange is about is the person the record names and not the "sub" the gateway holds.
     */
    #[Test]
    public function anExchangedTokenIsExchangedAgainForThePersonItIsAbout(): void
    {
        // Given
        $presented = $this->tokenOfThePerson();
        $exchanged = $this->exchanged($presented);

        // When
        $again = $this->exchanged($exchanged);

        // Then
        static::assertSame(self::subjectOf($presented), $this->introspect($again)['sub']);
    }

    /**
     * An access token of the client the person signed in to, addressed to the calendar (RFC 8707 §2): what
     * the gateway presents at the exchange, carrying the "sub" that client's sector sees its person under.
     */
    private function tokenOfThePerson(): string
    {
        $query =
            http_build_query(self::authorizationParameters(self::PERSON_CLIENT_ID, [
                'redirect_uri' => self::PERSON_REDIRECT_URI,
            ]))
            . '&resource='
            . rawurlencode(self::CALENDAR);
        $this->browser->request('GET', '/authorize?' . $query);
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::PERSON_REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: self::credentials(self::PERSON_CLIENT_ID, self::PERSON_SECRET),
        );
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return self::string(self::json($this->browser->getResponse())['access_token'] ?? null);
    }

    /**
     * RFC 8693 §2.1: the gateway exchanges what it was given for a token of its own, opaque, so that the
     * person this provider resolved is kept on a record and not written into the token.
     */
    private function exchanged(string $subjectToken): string
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token' => $subjectToken,
                'subject_token_type' => self::ACCESS_TOKEN_TYPE,
                'resource' => self::CALENDAR,
            ],
            server: self::credentials(self::GATEWAY_ID, self::GATEWAY_SECRET),
        );
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return self::string(self::json($this->browser->getResponse())['access_token'] ?? null);
    }

    /**
     * RFC 7662 §2.1: what the gateway is told of a token of its own.
     *
     * @return array<string, mixed>
     */
    private function introspect(string $token): array
    {
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => $token,
            ],
            server: self::credentials(self::GATEWAY_ID, self::GATEWAY_SECRET),
        );
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return self::json($this->browser->getResponse());
    }

    /**
     * The "sub" of an "at+jwt" of the first client, which is the pairwise identifier of its sector
     * (OIDC Core §8.1).
     */
    private static function subjectOf(string $accessToken): string
    {
        return self::string(self::claimsOf($accessToken)['sub'] ?? null);
    }

    private static function reread(User $user): User
    {
        $reread = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id);
        static::assertInstanceOf(User::class, $reread);

        return $reread;
    }

    /**
     * @return array<string, string>
     */
    private static function credentials(string $clientId, string $secret): array
    {
        return [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($clientId . ':' . $secret),
        ];
    }
}
