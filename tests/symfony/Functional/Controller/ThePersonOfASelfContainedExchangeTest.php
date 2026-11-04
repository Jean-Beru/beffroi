<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

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
 * RFC 8693 §2.1, §2.2.1, RFC 8707 §2, OIDC Core §8.1
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
     * RFC 7662 §2.2
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
     * RFC 8693 §2.1
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
     * OIDC Core §8.1
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
     * RFC 8707 §2
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
     * RFC 8693 §2.1
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
     * RFC 7662 §2.1
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
     * OIDC Core §8.1
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
