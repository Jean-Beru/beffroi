<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use App\Tests\Symfony\Fixture\TenantMailSigningKeys;
use Beffroi\Core\Domain\Event\MailSigningKeyRemoved;
use Beffroi\Core\Domain\Event\MailSigningKeySet;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function str_repeat;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0038, decision 0051: an administrator sets the keys the tenant signs its mail with, replaces them and
 * removes them, each write an act that names them; nothing answers the private half of a key.
 */
final class AdministrationApiMailSigningKeysTest extends AdministrationTestCase
{
    #[Test]
    public function anAdministratorSetsTheSmimeKeyAndTheActNamesThem(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->setSmime($token, TenantMailSigningKeys::asked());

        // Then
        static::assertSame(
            [Response::HTTP_OK, 'smime', true, [[null, 'alice-subject']]],
            [$response->getStatusCode(), ...self::members($response, ['format', 'current']), self::authored(MailSigningKeySet::NAME)],
        );
    }

    #[Test]
    public function noAnswerCarriesThePrivateHalfOfAKey(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $set = $this->setSmime($token, TenantMailSigningKeys::asked());
        $listed = $this->api('/tenant/mail-signing-keys', $token);

        // Then
        static::assertStringNotContainsString('PRIVATE KEY', $set->getContent() . $listed->getContent());
    }

    #[Test]
    public function theKeySetInPlaceOfAnotherIsCurrentAndTheOneItReplacedIsStillListed(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));
        $first = self::members($this->setSmime($token, TenantMailSigningKeys::asked()), ['fingerprint'])[0];
        $second = self::members($this->setSmime($token, TenantMailSigningKeys::asked('op-sender-next')), ['fingerprint'])[0];

        // When
        $response = $this->api('/tenant/mail-signing-keys', $token);

        // Then
        $keys = self::members($response, ['keys'])[0];
        static::assertIsArray($keys);
        $states = [];
        foreach ($keys as $key) {
            static::assertIsArray($key);
            $states[] = [$key['fingerprint'] ?? null, $key['current'] ?? null];
        }
        static::assertEqualsCanonicalizing([[$second, true], [$first, false]], $states);
    }

    #[Test]
    #[DataProvider('provideKeysThatDoNotSign')]
    public function aKeyAndACertificateThatDoNotSignForTheSenderAreRefusedAndNothingIsSet(string $name, ?string $certificateOf): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->setSmime($token, TenantMailSigningKeys::asked($name, $certificateOf));

        // Then
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, 'invalid_request', [], []],
            [
                $response->getStatusCode(),
                self::members($response, ['error'])[0],
                self::members($this->api('/tenant/mail-signing-keys', $token), ['keys'])[0],
                self::authored(MailSigningKeySet::NAME),
            ],
        );
    }

    /**
     * @return iterable<string, array{string, ?string}>
     */
    public static function provideKeysThatDoNotSign(): iterable
    {
        yield 'a key and the certificate of another key' => ['op-sender', 'op-sender-next'];
        yield 'a certificate that has expired' => ['op-sender-expired', null];
    }

    #[Test]
    public function anAdministratorDrawsTheOpenPgpKeyOfTheTenant(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/tenant/mail-signing-keys/pgp', $token, method: 'POST');

        // Then
        [$format, $published] = self::members($response, ['format', 'published']);
        static::assertSame([Response::HTTP_CREATED, 'pgp'], [$response->getStatusCode(), $format]);
        static::assertIsString($published);
        static::assertStringStartsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----', $published);
    }

    #[Test]
    public function anAdministratorRemovesAKeyAndTheActNamesThem(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));
        $fingerprint = self::members($this->setSmime($token, TenantMailSigningKeys::asked()), ['fingerprint'])[0];
        static::assertIsString($fingerprint);

        // When
        $response = $this->api('/tenant/mail-signing-keys/smime/' . $fingerprint, $token, method: 'DELETE');

        // Then
        static::assertSame(
            [Response::HTTP_OK, [], [[null, 'alice-subject']]],
            [
                $response->getStatusCode(),
                self::members($this->api('/tenant/mail-signing-keys', $token), ['keys'])[0],
                self::authored(MailSigningKeyRemoved::NAME),
            ],
        );
    }

    #[Test]
    public function aKeyTheTenantDoesNotHoldIsNotFound(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/tenant/mail-signing-keys/smime/' . str_repeat('A', 64), $token, method: 'DELETE');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $response->getStatusCode());
    }

    /**
     * @param array{private_key: string, certificates: string} $asked
     */
    private function setSmime(string $token, array $asked): Response
    {
        return $this->api('/tenant/mail-signing-keys/smime', $token, method: 'PUT', content: json_encode($asked, JSON_THROW_ON_ERROR));
    }
}
