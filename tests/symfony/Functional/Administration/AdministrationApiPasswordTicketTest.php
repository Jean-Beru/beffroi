<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use Beffroi\Core\Domain\Event\PasswordTicketIssued;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function str_starts_with;
use function strlen;
use function substr;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Decisions 0026 and 0038: an administrator issues the ticket that lets a person pose a new password, through the
 * administration API on the use case of the command of the console, an act of the person that names them.
 */
final class AdministrationApiPasswordTicketTest extends AdministrationTestCase
{
    #[Test]
    public function theLinkOfTheTicketAnAdministratorIssuedOpensThePageOfThatPassword(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::ticketPath($bob), $token, method: 'POST');

        // Then
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode());
        $this->browser->request('GET', self::pathOf($response));
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function theIssuingIsAnActOfThePersonThatNamesTheAdministrator(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api(self::ticketPath($bob), $token, method: 'POST');

        // Then
        static::assertSame([['bob-subject', 'alice-subject']], self::authored(PasswordTicketIssued::NAME));
    }

    #[Test]
    public function aSecondTicketTakesTheFirstAway(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));
        $first = self::pathOf($this->api(self::ticketPath($bob), $token, method: 'POST'));

        // When
        $this->api(self::ticketPath($bob), $token, method: 'POST');

        // Then
        $this->browser->request('GET', $first);
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aPersonTheTenantDoesNotHoldGetsNoTicket(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(sprintf('/users/%s/password-ticket', Uuid::v7()->toRfc4122()), $token, method: 'POST');

        // Then
        static::assertSame([Response::HTTP_NOT_FOUND, 'not_found', []], [
            $response->getStatusCode(),
            self::error($response),
            self::authored(PasswordTicketIssued::NAME),
        ]);
    }

    #[Test]
    public function aDisabledAccountGetsNoTicket(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $bob->disable(self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($bob);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::ticketPath($bob), $token, method: 'POST');

        // Then
        static::assertSame([Response::HTTP_CONFLICT, 'conflict', []], [
            $response->getStatusCode(),
            self::error($response),
            self::authored(PasswordTicketIssued::NAME),
        ]);
    }

    private static function ticketPath(User $person): string
    {
        return sprintf('/users/%s/password-ticket', $person->id->toRfc4122());
    }

    /**
     * The path of the link a ticket was answered with, under the origin of the issuer.
     */
    private static function pathOf(Response $response): string
    {
        $document = json_decode((string) $response->getContent(), true, 8, JSON_THROW_ON_ERROR);
        static::assertIsArray($document);
        $link = $document['link'] ?? null;
        static::assertIsString($link);
        static::assertTrue(str_starts_with($link, self::ISSUER . '/password/'), sprintf('The link %s is not under %s/password/.', $link, self::ISSUER));

        return substr($link, strlen(self::ISSUER));
    }

    private static function error(Response $response): mixed
    {
        $document = json_decode((string) $response->getContent(), true, 8, JSON_THROW_ON_ERROR);
        static::assertIsArray($document);

        return $document['error'] ?? null;
    }
}
