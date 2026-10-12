<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use function base64_encode;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ActsOfAPersonInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Domain\Event\IntrospectionAnswered;
use function http_build_query;
use const JSON_THROW_ON_ERROR;
use function json_encode;
use PHPUnit\Framework\Attributes\Test;
use function rawurlencode;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #641, RFC 8693 §2.2.1 and OIDC Core §8.1: the resources of this provider answer for the person a
 * self-contained exchanged token is about, which is the walk of issue #601 with the gateway's own tokens
 * carrying their claims instead of pointing at a row.
 *
 * Two clients and a sector each. The "sub" of the token the first one holds is the name that sector sees its
 * person under, and the token the exchange writes for the second one carries it, so looking it up under that
 * second client finds nobody: what answers is the person the exchange resolved when it read what was
 * presented, which the token says and nothing on disk does. What it says of that person it says to this
 * provider alone, the name the account carries being the one a pairwise kind exists to keep from a client.
 *
 * The two reads an exchanged token reaches are here. It is addressed to a resource and never to the client
 * that holds it (RFC 8707 §2, RFC 8693 §2.1), so the UserInfo endpoint of this provider refuses it whatever
 * it says of a person, as it refuses every token asked for a resource (ResourceIndicatorFlowTest).
 */
final class ThePersonOfASelfContainedExchangeTest extends BrowserTestCase
{
    private const string PERSON_CLIENT_ID = 'exchange-pairwise-app';

    private const string PERSON_SECRET = 'exchange-pairwise-secret-of-at-least-32-c';

    private const string PERSON_REDIRECT_URI = 'https://exchange-sector.test/callback';

    private const string GATEWAY_ID = 'exchange-pairwise-jwt-gateway';

    private const string GATEWAY_SECRET = 'exchange-jwt-gateway-secret-of-at-least-3';

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
    public function theIntrospectionOfASelfContainedExchangedTokenDescribesIt(): void
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
    public function theIntrospectionOfASelfContainedExchangedTokenIsInTheJournalOfItsPerson(): void
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
     * what the second exchange is about is the person the token says and not the "sub" the gateway holds.
     */
    #[Test]
    public function aSelfContainedExchangedTokenIsExchangedAgainForThePersonItIsAbout(): void
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
     * OIDC Core §8.1: the name the account carries is the one that links a person across sectors, so nothing
     * the gateway is handed carries it. What the provider wrote there it reads itself, and the gateway holds
     * the same two names it held before, the "sub" of the first client's sector and nothing of this one.
     */
    #[Test]
    public function aSelfContainedExchangedTokenNamesThePersonToNobodyHoldingIt(): void
    {
        // Given
        $presented = $this->tokenOfThePerson();

        // When
        $exchanged = $this->exchanged($presented);

        // Then
        static::assertStringNotContainsString(
            $this->alice->subject->value,
            self::string(json_encode(self::claimsOf($exchanged), JSON_THROW_ON_ERROR)),
        );
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
     * RFC 8693 §2.1: the gateway exchanges what it was given for a token of its own, self-contained, so
     * that the person this provider resolved travels in the token and is kept nowhere.
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
