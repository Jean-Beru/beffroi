<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0038: the provider addresses a token to the administration API of the tenant only for a person who
 * administers the tenant, signed in with a phishing-resistant proof, by a token bound to a key of the client.
 */
final class AdministrationApiFlowTest extends AdministrationTestCase
{
    #[Test]
    public function anAdministratorSignedInWithAPasskeyIsHandedATokenForTheApi(): void
    {
        // When
        $token = $this->administratorToken(self::user('alice'));

        // Then
        static::assertSame([self::API, 'phr'], [
            self::claimsOf($token)['aud'] ?? null,
            self::claimsOf($token)['acr'] ?? null,
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
}
