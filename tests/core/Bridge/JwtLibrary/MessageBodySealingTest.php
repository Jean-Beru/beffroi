<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\JwtLibrary;

use function base64_decode;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryMessageBodyOpener;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryMessageBodySealer;
use Beffroi\Core\Bridge\JwtLibrary\SealedMessageBody;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidJweException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use function explode;
use function json_decode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strtr;

/**
 * Decision 0020: what this provider writes to a transport leaves the process sealed, so that what a broker
 * keeps on its disk, and what the table of a transport holds, is worth nothing without the KMS.
 */
final class MessageBodySealingTest extends TestCase
{
    /**
     * A body of the shape a message of this provider carries: an address and a user agent, which every
     * event of the two packages holds by contract, and the two values decision 0011 seals in a column.
     */
    private const string BODY = 'a:2:{s:9:"ipAddress";s:12:"203.0.113.42";s:5:"email";s:17:"alice@acme.example";}';

    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private SealedKeyProvider $provider;

    private JwtLibraryMessageBodySealer $sealer;

    private JwtLibraryMessageBodyOpener $opener;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryTenantKeyRepository();
        $this->provider = new SealedKeyProvider($this->keys, Keys::sealer());
        $this->sealer = new JwtLibraryMessageBodySealer($this->provider, Algorithms::messageSealing());
        $this->opener = new JwtLibraryMessageBodyOpener($this->provider, Algorithms::messageSealing());
        $this->activeKey(Algorithms::messageSeal(), Keys::messagePair());
    }

    #[Test]
    public function aSealedBodyOpensBackToWhatWasSealed(): void
    {
        // When
        $sealed = $this->sealer->seal($this->tenant, self::BODY);

        // Then
        static::assertSame(self::BODY, $this->opener->open($this->tenant, $sealed));
    }

    /**
     * What DumpGivesNothingAwayTest asks of a column, asked of what leaves the process: none of the values
     * the body carried is in what the transport would carry.
     */
    #[Test]
    #[DataProvider('provideValuesOfTheBody')]
    public function aSealedBodyCarriesNoneOfTheValuesItHeld(string $value): void
    {
        // When
        $sealed = $this->sealer->seal($this->tenant, self::BODY);

        // Then
        static::assertStringNotContainsString($value, $sealed);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValuesOfTheBody(): iterable
    {
        yield 'the address' => ['203.0.113.42'];
        yield 'the email' => ['alice@acme.example'];
        yield 'the shape of the payload' => ['ipAddress'];
    }

    /**
     * RFC 7516 §4.1.6: the body names the key it was sealed to, and the scope it was sealed under, and
     * nothing else of its own. The scope is in the protected header because that header is what the
     * sealing authenticates.
     */
    #[Test]
    public function theProtectedHeaderNamesTheKeyTheAlgorithmsAndTheScope(): void
    {
        // Given
        $key = $this->provider->activeMessageKey($this->tenant, Algorithms::messageSeal());

        // When
        $header = self::protectedHeader($this->sealer->seal($this->tenant, self::BODY));

        // Then
        static::assertSame([
            'alg' => 'ECDH-ES+A256KW',
            'enc' => 'A256GCM',
            'kid' => $key->kid,
            SealedMessageBody::TENANT_HEADER => 'acme',
        ], [
            'alg' => $header['alg'] ?? null,
            'enc' => $header['enc'] ?? null,
            'kid' => $header['kid'] ?? null,
            SealedMessageBody::TENANT_HEADER => $header[SealedMessageBody::TENANT_HEADER] ?? null,
        ]);
    }

    /**
     * The pattern of beffroi#436: the scope is the authenticated data of the seal, so a body carried to
     * another scope fails to open instead of opening there.
     */
    #[Test]
    public function aBodyIsNotOpenedUnderAnotherScope(): void
    {
        // Given
        $sealed = $this->sealer->seal($this->tenant, self::BODY);

        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIs('The body of the message was sealed for another scope than tenant "other"; it is not opened here.');

        // When
        $this->opener->open(Fixtures::tenant('other'), $sealed);
    }

    /**
     * The one key that opens a body is the one its header names, and it is named among the keys the tenant
     * seals to: a set of keys is not a set of keys to try.
     */
    #[Test]
    public function aBodySealedToAKeyTheTenantNoLongerHoldsIsNotOpened(): void
    {
        // Given
        $sealed = $this->sealer->seal($this->tenant, self::BODY);
        $key = $this->provider->activeMessageKey($this->tenant, Algorithms::messageSeal());
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());
        $this->keys->save($key);

        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIsOrContains('seals nothing to');

        // When
        $this->opener->open($this->tenant, $sealed);
    }

    #[Test]
    public function aBodyThatIsNotACompactJweIsNotOpened(): void
    {
        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIs('The body of the message is not a compact JWE.');

        // When
        $this->opener->open($this->tenant, self::BODY);
    }

    /**
     * A tenant that has no key to seal to writes nothing: the refusal comes from the key provider and is
     * not turned into a body in the clear.
     */
    #[Test]
    public function nothingIsSealedForATenantWithoutAKey(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIsOrContains('has no active MESSAGE-SEAL key');

        // When
        $this->sealer->seal(Fixtures::tenant('other'), self::BODY);
    }

    /**
     * @return array<string, mixed>
     */
    private static function protectedHeader(string $sealed): array
    {
        $decoded = base64_decode(strtr(explode('.', $sealed)[0], '-_', '+/'), true);
        static::assertIsString($decoded);
        $header = json_decode($decoded, true);
        static::assertIsArray($header);
        $members = [];
        foreach ($header as $member => $value) {
            static::assertIsString($member);
            $members[$member] = $value;
        }

        return $members;
    }

    private function activeKey(KeyAlgorithmInterface $algorithm, GeneratedKeyPair $pair): TenantKey
    {
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            $algorithm,
            $pair->publicJwk,
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $this->keys->save($key);

        return $key;
    }
}
