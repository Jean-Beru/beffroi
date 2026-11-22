<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use function array_key_exists;
use Beffroi\Core\Domain\Event\TenantContactChanged;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0038, NIST SP 800-63B-4 §4.6: an administrator sets the contact the tenant gives its people when it tells
 * them of a change to their account, and takes it back.
 */
final class AdministrationApiTenantContactTest extends AdministrationTestCase
{
    #[Test]
    public function anAdministratorSetsTheContactAndTheActNamesThem(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/tenant/contact', $token, method: 'PUT', content: '{"contact": "security@acme.example"}');

        // Then
        static::assertSame(
            [Response::HTTP_OK, 'security@acme.example', [[null, 'alice-subject']]],
            [$response->getStatusCode(), self::members($response, ['contact'])[0], self::authored(TenantContactChanged::NAME)],
        );
    }

    #[Test]
    public function theTenantReadsTheContactItGives(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));
        $this->api('/tenant/contact', $token, method: 'PUT', content: '{"contact": "security@acme.example"}');

        // When
        $response = $this->api('/tenant', $token);

        // Then
        static::assertSame('security@acme.example', self::members($response, ['contact'])[0]);
    }

    #[Test]
    public function aTenantThatGivesNoContactReadsNone(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/tenant', $token);

        // Then
        static::assertSame([true, null], [array_key_exists('contact', self::json($response)), self::members($response, ['contact'])[0]]);
    }

    #[Test]
    #[DataProvider('provideRefusedContacts')]
    public function aContactThatCannotBeWrittenIntoAMessageIsRefused(string $content): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/tenant/contact', $token, method: 'PUT', content: $content);

        // Then
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, 'invalid_request', []],
            [$response->getStatusCode(), self::members($response, ['error'])[0], self::authored(TenantContactChanged::NAME)],
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedContacts(): iterable
    {
        yield 'no contact named' => ['{}'];
        yield 'a contact that is no string' => ['{"contact": 42}'];
        yield 'two lines' => ['{"contact": "security@acme.example\nhttps://evil.example"}'];
        yield 'nothing' => ['{"contact": ""}'];
        yield 'no JSON object' => ['security@acme.example'];
    }

    #[Test]
    public function anAdministratorTakesTheContactBackAndTheActNamesThem(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));
        $this->api('/tenant/contact', $token, method: 'PUT', content: '{"contact": "security@acme.example"}');

        // When
        $response = $this->api('/tenant/contact', $token, method: 'DELETE');

        // Then
        static::assertSame(
            [
                Response::HTTP_OK,
                null,
                [
                    [null, 'alice-subject'],
                    [null, 'alice-subject'],
                ],
            ],
            [$response->getStatusCode(), self::members($response, ['contact'])[0], self::authored(TenantContactChanged::NAME)],
        );
    }

    #[Test]
    public function takingBackAContactTheTenantDoesNotGiveIsNoAct(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/tenant/contact', $token, method: 'DELETE');

        // Then
        static::assertSame([Response::HTTP_OK, []], [$response->getStatusCode(), self::authored(TenantContactChanged::NAME)]);
    }
}
