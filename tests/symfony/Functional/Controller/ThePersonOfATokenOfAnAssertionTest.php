<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

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
 * Issue #831 and RFC 7523 §2.1: a token issued on the assertion of an issuer the tenant trusts is the token of
 * a person nobody signed in for here, and the resources of this provider answer for that person all the same,
 * in either shape. Its introspection is a read of that person (issue #589), and once the account is disabled
 * the token is inactive, as every other token that names that person is; so is a token a gateway was given
 * for it in an exchange (RFC 8693 §2.1), which names the same person.
 *
 * The issuer and its two job runners are declared by the test kernel; its keys are the ones of the suite,
 * named before the kernel boots, the way the attested registration names the keys of its authority.
 */
final class ThePersonOfATokenOfAnAssertionTest extends BrowserTestCase
{
    private const string GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    private const string CALENDAR = 'https://cal.example.com/';

    /**
     * The "sub" of the assertions: the name the issuer knows its person by, which a linked identity of its
     * source turns into a user of this tenant (decision 0002).
     */
    private const string EMPLOYEE = 'employee-42';

    private const string GATEWAY_ID = 'person-gateway-app';

    private const string GATEWAY_SECRET = 'person-gateway-secret-of-at-least-32-chara';

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

    /**
     * Issue #589: a read that describes a person is an act of this provider, and the token of an assertion
     * describes the person the assertion was validated for, so the journal of that person holds it.
     */
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
     * RFC 7662 §2.2: a person this provider no longer serves is refused wherever a token names them, so the
     * token of an assertion about them is "active": false from the moment the account is disabled.
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
     * RFC 8693 §2.1: what a gateway is given for the token of an assertion names the person that token
     * names, so the account disabled since makes it inactive as well.
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
     * RFC 7523 §2.1: the job runner presents an assertion of the trusted issuer about the employee, and
     * receives a token for the user the linked identity names, addressed to the calendar.
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
     * RFC 8693 §2.1: the gateway registered to act for a user exchanges the token of the job runner for an
     * opaque token of its own, addressed to the same calendar.
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
     * RFC 7662 §2.1: what a client is told of a token of its own.
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
