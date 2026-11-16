<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use Beffroi\Oidc\Tests\Fixture\Proofs;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\Clock;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0038: the provider addresses a token to the administration API of the tenant only for a person who
 * administers the tenant, signed in with a phishing-resistant proof, by a token bound to a key of the client.
 */
final class AdministrationApiFlowTest extends PasskeyTestCase
{
    private const string CLIENT = 'administration-app';

    private const string REDIRECT_URI = 'https://administration.test/callback';

    private const string API = 'https://admin.op.test';

    /**
     * The origin of the issuer of the test kernel, which a proof names in its "htu" (RFC 9449 §4.3).
     */
    private const string ISSUER = 'https://op.test';

    /**
     * A proof is used once (RFC 9449 §11.1), so each one made here carries an identifier of its own.
     */
    private static int $proofs = 0;

    #[Test]
    public function anAdministratorSignedInWithAPasskeyIsHandedATokenForTheApi(): void
    {
        // Given
        self::signingKey();
        $device = self::device();
        $alice = self::user('alice');
        self::administers($alice);
        $this->enrol($alice, $device);
        $code = $this->codeAfterAPasskeyLogin($device);

        // When
        $this->browser->request('POST', '/token', self::tokenParameters($code), server: [
            'HTTP_DPOP' => $this->proof(),
        ]);

        // Then
        $tokens = self::json($this->browser->getResponse());
        static::assertSame([self::API, 'phr'], [
            self::claimsOf(self::string($tokens['access_token'] ?? null))['aud'] ?? null,
            self::claimsOf(self::string($tokens['access_token'] ?? null))['acr'] ?? null,
        ]);
    }

    /**
     * RFC 6749 §4.1.2.1: the client is told access_denied, once the person signed in.
     */
    #[Test]
    public function aPersonWhoDoesNotAdministerTheTenantIsDeniedTheApi(): void
    {
        // Given
        $device = self::device();
        $this->enrol(self::user('alice'), $device);

        // When
        $response = $this->afterAPasskeyLogin($device);

        // Then
        static::assertSame('access_denied', self::redirectedQuery($response)['error'] ?? null);
    }

    /**
     * RFC 9449 §6: a token for the API is bound to a key of the client, and a request that proves none is refused one.
     */
    #[Test]
    public function aTokenForTheApiIsNeverABearerToken(): void
    {
        // Given
        self::signingKey();
        $device = self::device();
        $alice = self::user('alice');
        self::administers($alice);
        $this->enrol($alice, $device);
        $code = $this->codeAfterAPasskeyLogin($device);

        // When
        $this->browser->request('POST', '/token', self::tokenParameters($code));

        // Then
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, 'invalid_target'],
            [$this->browser->getResponse()->getStatusCode(), self::json($this->browser->getResponse())['error'] ?? null],
        );
    }

    /**
     * The person a member of the group the test kernel names to administer its tenant, a membership the tenant holds.
     */
    private static function administers(User $user): void
    {
        $group = new Group(Uuid::v7(), self::tenant(), 'administrators', GroupSource::Local, Clock::get()->now());
        self::service('test.beffroi.groups', GroupRepositoryInterface::class)->save($group);
        self::service('test.beffroi.group_memberships', GroupMembershipRepositoryInterface::class)
            ->save(
                new GroupMembership(Uuid::v7(), $group, $user, GroupSource::Local, Clock::get()->now()),
            );
    }

    private function codeAfterAPasskeyLogin(SoftwareAuthenticator $device): string
    {
        return self::redirectedQuery($this->afterAPasskeyLogin($device))['code'] ?? static::fail('The client got no code.');
    }

    /**
     * A browser that holds no session asks for the API, its person signs in with the passkey, and the interaction
     * goes on to the client.
     */
    private function afterAPasskeyLogin(SoftwareAuthenticator $device): Response
    {
        $this->forgetTheBrowser();
        $this->browser->request('GET', '/authorize', self::authorizationParameters(self::CLIENT, [
            'redirect_uri' => self::REDIRECT_URI,
            'resource' => self::API,
        ]));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->loginWithPasskey($interaction, $device);
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        return $this->browser->getResponse();
    }

    private function proof(): string
    {
        return Proofs::proof('POST', self::ISSUER . '/token', Clock::get()->now(), null, [
            'jti' => 'administration-proof-' . self::$proofs++,
        ]);
    }

    /**
     * @return array<string, string>
     */
    private static function tokenParameters(string $code): array
    {
        return [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => self::REDIRECT_URI,
            'code_verifier' => self::CODE_VERIFIER,
            'client_id' => self::CLIENT,
        ];
    }
}
