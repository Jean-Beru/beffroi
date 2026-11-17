<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Event\RegisteredClientDeleted;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\ClientStoreInterface;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §1.2, RFC 7592 §2.3, Decision 0038: an administrator reads what the initial access token that registered a
 * client gave it, and deletes a client that registered itself, through the administration API on what the commands
 * of the console call, the deletion an act of the tenant that names them.
 */
final class AdministrationApiClientsTest extends AdministrationTestCase
{
    private const string REGISTERED = 'registered-invoices';

    #[Test]
    public function aRegisteredClientIsShownWithWhatItsInitialAccessTokenGaveIt(): void
    {
        // Given
        self::registered(['resources' => ['https://api.example/invoices']]);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/clients/' . self::REGISTERED, $token);

        // Then
        static::assertSame([['resources' => ['https://api.example/invoices']]], self::members($response, ['granted']));
    }

    #[Test]
    public function anAdministratorDeletesAClientThatRegisteredItself(): void
    {
        // Given
        self::registered();
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/clients/' . self::REGISTERED, $token, method: 'DELETE');

        // Then
        self::reload();
        static::assertSame(
            [Response::HTTP_OK, null],
            [$response->getStatusCode(), self::service('test.beffroi.client_store', ClientStoreInterface::class)->findRecord(self::tenant(), self::REGISTERED)],
        );
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function deletingAClientIsAnActOfTheTenantThatNamesTheAdministrator(): void
    {
        // Given
        self::registered();
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api('/clients/' . self::REGISTERED, $token, method: 'DELETE');

        // Then
        static::assertSame([[null, 'alice-subject']], self::authored(RegisteredClientDeleted::NAME));
    }

    #[Test]
    public function aClientTheDeploymentDeclaresIsNotDeleted(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/clients/oidc-demo', $token, method: 'DELETE');

        // Then
        static::assertSame([Response::HTTP_CONFLICT, 'conflict', []], [
            $response->getStatusCode(),
            self::members($response, ['error'])[0],
            self::authored(RegisteredClientDeleted::NAME),
        ]);
    }

    #[Test]
    public function theClientTheAdministratorActsThroughIsNotDeleted(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/clients/' . self::CLIENT, $token, method: 'DELETE');

        // Then
        static::assertSame([Response::HTTP_CONFLICT, 'conflict', []], [
            $response->getStatusCode(),
            self::members($response, ['error'])[0],
            self::authored(RegisteredClientDeleted::NAME),
        ]);
    }

    #[Test]
    public function aClientTheTenantDoesNotHoldIsNotFound(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/clients/nobody', $token, method: 'DELETE');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $response->getStatusCode());
    }

    /**
     * @param array<string, mixed>|null $granted
     */
    private static function registered(?array $granted = null): void
    {
        self::service('test.beffroi.client_store', ClientStoreInterface::class)
            ->save(new ClientRecord(
                Uuid::v7(),
                self::tenant(),
                self::REGISTERED,
                [
                    'client_name' => 'Invoices',
                    'redirect_uris' => ['https://invoices.example/callback'],
                    'token_endpoint_auth_method' => 'none',
                ],
                [],
                null,
                DrawnSecret::digestOf(Secrets::draw()),
                self::now(),
                granted: $granted,
            ));
        self::reload();
    }
}
