<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use function http_build_query;
use function rawurlencode;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ActsOfAPersonInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Domain\Event\TokenRevoked;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #593, RFC 8693 §2.1 and RFC 7009 §2.1: a token whose subject a client named is given back, and the
 * act of that revocation is in the journal of the person it was issued for.
 *
 * The "sub" such a token keeps is a name only the client the presented token was written for holds (OIDC
 * Core §8.1), so nothing can read it back under the client that asked: what the exchange resolved when it
 * read what was presented is kept on the record, and that is what the revocation names. A token nobody
 * signed in for still writes its act, naming nobody.
 */
final class TheRevocationOfAnExchangedTokenTest extends BrowserTestCase
{
    private const string GATEWAY_ID = 'person-gateway-app';

    private const string GATEWAY_SECRET = 'person-gateway-secret-of-at-least-32-chara';

    private const string CALENDAR = 'https://cal.example.com/';

    private const string ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

    private const string PERSON_CLIENT_ID = 'resource-app';

    private const string PERSON_REDIRECT_URI = 'https://resource.test/callback';

    #[Test]
    public function theRevocationOfAnExchangedTokenIsInTheJournalOfItsPerson(): void
    {
        // Given
        self::signingKey();
        $alice = self::user('alice');
        $this->signIn($alice);
        $exchanged = $this->exchanged($this->tokenOfAPerson());

        // When
        $this->revoke($exchanged);

        // Then
        static::assertCount(1, self::service('test.beffroi.acts', ActsOfAPersonInterface::class)
            ->lastOf(
                self::reread($alice),
                [TokenRevoked::NAME],
                10,
            ));
    }

    /**
     * RFC 6749 §4.4: a token a client holds for itself is about nobody, and neither is what an exchange of
     * it issues. The act is written all the same, naming no person, which is what the journal does with
     * every act that concerns none.
     */
    #[Test]
    public function theRevocationOfATokenNobodySignedInForNamesNobody(): void
    {
        // Given
        self::signingKey();
        $exchanged = $this->exchanged($this->tokenOfAService());

        // When
        $this->revoke($exchanged);

        // Then
        static::assertSame([null], self::subjectsOfTheRevocations());
    }

    /**
     * An access token of a client the person signed in to, addressed to the calendar (RFC 8707 §2): what a
     * gateway presents at the exchange, and what an exchange narrows what it is addressed to inside of.
     */
    private function tokenOfAPerson(): string
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
            server: self::credentials(self::PERSON_CLIENT_ID, 'resource-secret-of-at-least-32-characters'),
        );
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return self::string(self::json($this->browser->getResponse())['access_token'] ?? null);
    }

    /**
     * RFC 6749 §4.4: a token a service holds for itself, of the one client of the test kernel whose own
     * tokens are opaque, so that the presented token is read from its record as a gateway reads one.
     */
    private function tokenOfAService(): string
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'client_credentials',
                'scope' => 'invoices.read',
                'resource' => self::CALENDAR,
            ],
            server: self::credentials('service-opaque-app', 'service-opaque-secret-of-at-least-32-chars'),
        );
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return self::string(self::json($this->browser->getResponse())['access_token'] ?? null);
    }

    /**
     * RFC 8693 §2.1: the gateway exchanges the token it presents for one of its own, opaque, so that it can
     * be given back at the revocation endpoint (RFC 7009 §2.2.1).
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

    private function revoke(string $token): void
    {
        $this->browser->request(
            'POST',
            '/revoke',
            [
                'token' => $token,
                'token_type_hint' => TokenRevoked::ACCESS_TOKEN,
            ],
            server: self::credentials(self::GATEWAY_ID, self::GATEWAY_SECRET),
        );
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));
        self::reload();
    }

    /**
     * The person each act of a revocation names, read from the rows: an act that names nobody is not an act
     * the journal of a person answers for.
     *
     * @return list<string|null>
     */
    private static function subjectsOfTheRevocations(): array
    {
        $subjects = self::service('doctrine.dbal.default_connection', Connection::class)
            ->fetchFirstColumn(
                'SELECT subject FROM beffroi_journal WHERE act = ?',
                [TokenRevoked::NAME],
            );
        $read = [];
        foreach ($subjects as $subject) {
            $read[] = $subject === null ? null : self::string($subject);
        }

        return $read;
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
