<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use function array_map;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Event\InitialAccessTokenIssued;
use Beffroi\Oidc\Domain\Event\InitialAccessTokenRevoked;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\IssuedInitialAccessTokensInterface;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use function count;
use function is_array;
use function is_string;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Clock\Clock;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §1.2, Decision 0038: an administrator issues, lists and revokes the initial access tokens of the tenant
 * through the administration API, on what the commands of the console call, each write an act of the tenant that names
 * them.
 */
final class AdministrationApiInitialAccessTokensTest extends AdministrationTestCase
{
    private const string ASKED = '{"name":"The terminal of the second floor","registrations":1,"days":7,"administration":true}';

    #[Test]
    public function theAnswerToAnIssuanceCarriesTheValueOfTheToken(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/initial-access-tokens', $token, method: 'POST', content: self::ASKED);

        // Then
        [$value, $administration] = self::members($response, ['value', 'administration']);
        static::assertSame(
            [Response::HTTP_CREATED, true, true],
            [$response->getStatusCode(), is_string($value) && DrawnSecret::isValue($value), $administration],
        );
    }

    #[Test]
    public function theTokensOfTheTenantAreListedWithoutTheirValue(): void
    {
        // Given
        $issued = self::issued('The team that integrates');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/initial-access-tokens', $token);

        // Then
        $tokens = self::members($response, ['initial_access_tokens'])[0];
        static::assertIsArray($tokens);
        static::assertSame(
            [[$issued->id->toRfc4122(), 'The team that integrates', true, false]],
            array_map(
                static fn (mixed $listed): array => (
                    is_array($listed)
                        ? [$listed['id'] ?? null, $listed['name'] ?? null, $listed['authorises_a_registration'] ?? null, isset($listed['value'])]
                        : []
                ),
                $tokens,
            ),
        );
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function issuingATokenIsAnActOfTheTenantThatNamesTheAdministrator(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api('/initial-access-tokens', $token, method: 'POST', content: self::ASKED);

        // Then
        static::assertSame([[null, 'alice-subject']], self::authored(InitialAccessTokenIssued::NAME));
    }

    #[Test]
    #[DataProvider('provideTokensAskedAmiss')]
    public function aTokenAskedAmissIsNotIssued(string $asked): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/initial-access-tokens', $token, method: 'POST', content: $asked);

        // Then
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, 'invalid_request', 0],
            [
                $response->getStatusCode(),
                self::members($response, ['error'])[0],
                count([...self::service('test.beffroi.initial_access_tokens', IssuedInitialAccessTokensInterface::class)->issuedIn(self::tenant())]),
            ],
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTokensAskedAmiss(): iterable
    {
        yield 'without its name' => ['{"registrations":1,"days":7}'];
        yield 'without how long it is worth anything' => ['{"name":"invoices","registrations":1}'];
        yield 'worth no day' => ['{"name":"invoices","registrations":1,"days":0}'];
        yield 'worth no registration' => ['{"name":"invoices","registrations":0,"days":7}'];
        yield 'worth more days than a date holds' => ['{"name":"invoices","registrations":1,"days":9223372036854775807}'];
        yield 'giving what no token gives' => ['{"name":"invoices","registrations":1,"days":7,"granted":{"scope":"openid"}}'];
        yield 'giving the administration API among its resources' => [sprintf(
            '{"name":"invoices","registrations":1,"days":7,"granted":{"resources":["%s"]}}',
            self::API,
        )];
        yield 'not a JSON object' => ['"invoices"'];
    }

    #[Test]
    public function anAdministratorRevokesAToken(): void
    {
        // Given
        $issued = self::issued('The team that integrates');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(sprintf('/initial-access-tokens/%s', $issued->id->toRfc4122()), $token, method: 'DELETE');

        // Then
        self::reload();
        static::assertSame(
            [Response::HTTP_OK, false, true],
            [
                $response->getStatusCode(),
                self::members($response, ['authorises_a_registration'])[0],
                self::service('test.beffroi.initial_access_tokens', IssuedInitialAccessTokensInterface::class)->find(self::tenant(), $issued->id)?->isRevoked(),
            ],
        );
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function revokingATokenIsAnActOfTheTenantThatNamesTheAdministrator(): void
    {
        // Given
        $issued = self::issued('The team that integrates');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api(sprintf('/initial-access-tokens/%s', $issued->id->toRfc4122()), $token, method: 'DELETE');

        // Then
        static::assertSame([[null, 'alice-subject']], self::authored(InitialAccessTokenRevoked::NAME));
    }

    #[Test]
    public function aTokenTheTenantDidNotIssueIsNotFound(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(sprintf('/initial-access-tokens/%s', Uuid::v7()->toRfc4122()), $token, method: 'DELETE');

        // Then
        static::assertSame([Response::HTTP_NOT_FOUND, []], [$response->getStatusCode(), self::authored(InitialAccessTokenRevoked::NAME)]);
    }

    private static function issued(string $name): InitialAccessToken
    {
        $now = Clock::get()->now();
        $token = new InitialAccessToken(
            Uuid::v7(),
            self::tenant(),
            DrawnSecret::digestOf(Secrets::draw()),
            $name,
            1,
            $now,
            $now->modify('+30 days'),
        );
        self::service('test.beffroi.initial_access_tokens', InitialAccessTokenRepositoryInterface::class)->save($token);

        return $token;
    }
}
