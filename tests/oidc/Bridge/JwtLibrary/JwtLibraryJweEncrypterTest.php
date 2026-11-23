<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Bridge\JwtLibrary;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryJweEncrypter;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Tests\Fixture\ClientEncryption;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7516 §7.1
 */
final class JwtLibraryJweEncrypterTest extends TestCase
{
    private JwtLibraryJweEncrypter $encrypter;

    protected function setUp(): void
    {
        $this->encrypter = new JwtLibraryJweEncrypter(Algorithms::encryption()->manager());
    }

    /**
     * RFC 7516 §5.1
     */
    #[Test]
    public function theClientOpensWhatIsEncryptedToItsKey(): void
    {
        // Given
        /** @var array<string, mixed> $recipient */
        $recipient = ClientEncryption::privateKey()->toPublic()->all();

        // When
        $jwe = $this->encrypter->encrypt($recipient, ClientEncryption::registration(), 'the document');

        // Then
        static::assertSame('the document', ClientEncryption::open($jwe)['payload']);
    }

    /**
     * RFC 7518 §4.6, §6.2.1
     *
     * @param array<string, mixed> $recipient
     */
    #[Test]
    #[DataProvider('provideKeysThatReceiveNoJwe')]
    public function aKeyThatReceivesNoJweLeavesTheClientWithoutAKey(array $recipient): void
    {
        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIs('The document could not be encrypted under "ECDH-ES+A256KW": the key it is addressed to does not receive one.');

        // When
        $this->encrypter->encrypt($recipient, ClientEncryption::registration(), 'the document');
    }

    /**
     * RFC 7518 §4.6, §6.2.1
     *
     * @param array<string, mixed> $recipient
     */
    #[Test]
    #[DataProvider('provideKeysThatReceiveNoJwe')]
    public function aKeyThatReceivesNoJweIsToldSoBeforeAnyDocumentIsEncrypted(array $recipient): void
    {
        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIs('The document could not be encrypted under "ECDH-ES+A256KW": the key it is addressed to does not receive one.');

        // When
        $this->encrypter->assertReceives($recipient, ClientEncryption::registration());
    }

    /**
     * RFC 7518 §4.6
     */
    #[Test]
    public function aKeyThatReceivesAJweIsTakenAsItIs(): void
    {
        // Given
        /** @var array<string, mixed> $recipient */
        $recipient = ClientEncryption::privateKey()->toPublic()->all();

        // Then
        $this->expectNotToPerformAssertions();

        // When
        $this->encrypter->assertReceives($recipient, ClientEncryption::registration());
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideKeysThatReceiveNoJwe(): iterable
    {
        yield 'a point off its curve' => [ClientEncryption::keyOffItsCurve()];
        yield 'a curve ECDH-ES does not use' => [[
            'kty' => 'EC',
            'crv' => 'P-192',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]];
        yield 'a coordinate missing' => [[
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
        ]];
    }
}
