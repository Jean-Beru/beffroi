<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ActsOfAPersonInterface;
use Beffroi\Core\Port\LinkedIdentityRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Domain\Event\IntrospectionAnswered;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\TrustedIssuers;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\Clock;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7523 §2.1, RFC 8693 §2.1
 */
final class ThePersonOfATokenOfAnAssertionTest extends BrowserTestCase
{
    private const string GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    private const string CALENDAR = 'https://cal.example.com/';

    private const string EMPLOYEE = 'employee-42';

    private const string GATEWAY_ID = 'person-gateway-app';

    private const string GATEWAY_SECRET = 'person-gateway-secret-of-at-least-32-chara';

    private const string SERVICE_GATEWAY_ID = 'gateway-app';

    private const string SERVICE_GATEWAY_SECRET = 'gateway-secret-of-at-least-32-characters-l';

    private User $alice;

    protected function setUp(): void
    {
        $_SERVER['BEFFROI_TEST_TRUSTED_ISSUER_JWKS'] = base64_encode(json_encode(
            ['keys' => ClientAssertions::publishedKeys()->keys],
            JSON_THROW_ON_ERROR,
        ));
        parent::setUp();
        self::signingKey();
        $this->alice = self::user('alice');
        $now = Clock::get()->now();
        self::service('test.beffroi.linked_identities', LinkedIdentityRepositoryInterface::class)
            ->save(new LinkedIdentity(Uuid::v7(), $this->alice, TrustedIssuers::PROVIDER, self::EMPLOYEE, [], $now, $now));
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['BEFFROI_TEST_TRUSTED_ISSUER_JWKS'], $_ENV['BEFFROI_TEST_TRUSTED_ISSUER_JWKS']);
    }

    #[Test]
    #[DataProvider('provideJobRunners')]
    public function theIntrospectionOfATokenOfAnAssertionIsInTheJournalOfItsPerson(string $clientId, string $secret): void
    {
        // Given
        $token = $this->tokenOfAnAssertion($clientId, $secret);

        // When
        $this->introspect($token, $clientId, $secret);
        self::reload();

        // Then
        static::assertCount(1, self::service('test.beffroi.acts', ActsOfAPersonInterface::class)
            ->lastOf(self::reread($this->alice), [IntrospectionAnswered::NAME], 10));
    }

    /**
     * RFC 7662 §2.2
     */
    #[Test]
    #[DataProvider('provideJobRunners')]
    public function aTokenOfAnAssertionIsInactiveOnceItsPersonIsDisabled(string $clientId, string $secret): void
    {
        // Given
        $token = $this->tokenOfAnAssertion($clientId, $secret);
        $this->disableAlice();

        // When
        $described = $this->introspect($token, $clientId, $secret);

        // Then
        static::assertSame(
            [
                'active' => false,
            ],
            $described,
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideJobRunners(): iterable
    {
        yield 'opaque' => ['assertion-opaque-app', 'assertion-opaque-secret-of-at-least-32-ch'];
        yield 'at+jwt' => ['assertion-app', 'assertion-secret-of-at-least-32-character'];
    }

    /**
     * RFC 8693 §2.1
     */
    #[Test]
    public function aTokenExchangedForATokenOfAnAssertionIsInactiveOnceItsPersonIsDisabled(): void
    {
        // Given
        $exchanged = $this->exchanged($this->tokenOfAnAssertion('assertion-app', 'assertion-secret-of-at-least-32-character'));
        $this->disableAlice();

        // When
        $described = $this->introspect($exchanged, self::GATEWAY_ID, self::GATEWAY_SECRET);

        // Then
        static::assertSame(
            [
                'active' => false,
            ],
            $described,
        );
    }

    /**
     * RFC 8693 §2.1
     */
    #[Test]
    public function aGatewayNotRegisteredToActForAUserIsRefusedATokenOfAnAssertion(): void
    {
        // Given
        $token = $this->tokenOfAnAssertion('assertion-app', 'assertion-secret-of-at-least-32-character');

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token' => $token,
                'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
                'resource' => self::CALENDAR,
            ],
            server: self::credentials(self::SERVICE_GATEWAY_ID, self::SERVICE_GATEWAY_SECRET),
        );

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame('invalid_request', self::json($this->browser->getResponse())['error'] ?? null);
    }

    /**
     * RFC 7523 §2.1
     */
    private function tokenOfAnAssertion(string $clientId, string $secret): string
    {
        $assertion = TrustedIssuers::assertion(self::EMPLOYEE, self::tenant()->issuer->value, Clock::get()->now(), [
            'jti' => Uuid::v4()->toRfc4122(),
        ]);
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => self::GRANT_TYPE,
                'assertion' => $assertion,
                'scope' => 'invoices.read',
                'resource' => self::CALENDAR,
            ],
            server: self::credentials($clientId, $secret),
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
                'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
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
    private function introspect(string $token, string $clientId, string $secret): array
    {
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => $token,
            ],
            server: self::credentials($clientId, $secret),
        );
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return self::json($this->browser->getResponse());
    }

    private function disableAlice(): void
    {
        $alice = self::reread($this->alice);
        $alice->disable(Clock::get()->now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($alice);
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
