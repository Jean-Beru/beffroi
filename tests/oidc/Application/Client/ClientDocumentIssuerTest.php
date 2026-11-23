<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Client\AddressedFormat;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Client\ResponseFormat;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\ClientEncryption;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeClientJwksFetcher;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §3.1.3.7, §5.3.2, JARM §2.1
 */
final class ClientDocumentIssuerTest extends TestCase
{
    private Tenant $tenant;

    private Jwts $jwts;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->jwts = new Jwts($this->tenant);
    }

    #[Test]
    public function aDocumentThatIsNeitherSignedNorEncryptedIsNotMintedHere(): void
    {
        // Given
        $client = Clients::public($this->tenant);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('registered neither a signature nor an encryption for this document');

        // When
        $this->jwts->documents->issue($client, new AddressedFormat(ResponseFormat::unsigned()), [
            'sub' => 'alice',
        ]);
    }

    #[Test]
    public function aShapeThatEncryptsNothingIsAddressedWithoutReadingAKey(): void
    {
        // Given
        $client = Clients::public($this->tenant);
        $format = ResponseFormat::signed();

        // When
        $addressed = $this->jwts->documents->address($client, $format);

        // Then
        static::assertSame($format, $addressed->format);
    }

    #[Test]
    public function aClientWhosePublishedKeysNoLongerFitIsToldSoAndNothingLeaves(): void
    {
        // Given
        $client = Clients::withKeys($this->tenant, 'moved-on', jwksUri: new ClientUri('https://moved.example/jwks'));
        /** @var list<array<string, mixed>> $signingOnly */
        $signingOnly = [[
            ...ClientEncryption::privateKey()->toPublic()->all(),
            'use' => 'sig',
        ]];
        $documents = $this->jwts->documentsFor(new FakeClientJwksFetcher([new ClientJwks($signingOnly)]));

        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIs('The client "moved-on" publishes no key a document encrypted under "ECDH-ES+A256KW" can be addressed to.');

        // When
        $documents->address($client, ResponseFormat::signed(null, ClientEncryption::registration()));
    }

    /**
     * RFC 7518 §4.6
     */
    #[Test]
    public function aClientWhoseKeyReceivesNoJweIsToldSoWhenTheDocumentIsAddressed(): void
    {
        // Given
        $format = ResponseFormat::signed(null, ClientEncryption::registration());
        $client = Clients::encryptedFor($this->tenant, $format, clientId: 'off-its-curve', jwks: new ClientJwks([ClientEncryption::keyOffItsCurve()]));

        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIs('The document could not be encrypted under "ECDH-ES+A256KW": the key it is addressed to does not receive one.');

        // When
        $this->jwts->documents->address($client, $format);
    }

    #[Test]
    public function aClientWhoseKeysCannotBeReadIsToldSoWhenTheDocumentIsAddressed(): void
    {
        // Given
        $client = Clients::withKeys($this->tenant, 'unreachable', jwksUri: new ClientUri('https://unreachable.example/jwks'));
        $fetcher = new FakeClientJwksFetcher([ClientEncryption::publishedKeys()]);
        $fetcher->failure = new ClientKeysUnavailableException('https://unreachable.example/jwks cannot be reached.');
        $documents = $this->jwts->documentsFor($fetcher);

        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIs('https://unreachable.example/jwks cannot be reached.');

        // When
        $documents->address($client, ResponseFormat::signed(null, ClientEncryption::registration()));
    }

    #[Test]
    public function aDocumentIsStruckForTheKeyReadWhenItWasAddressed(): void
    {
        // Given
        $client = Clients::withKeys($this->tenant, 'flaky', jwksUri: new ClientUri('https://flaky.example/jwks'));
        $fetcher = new FakeClientJwksFetcher([ClientEncryption::publishedKeys()]);
        $documents = $this->jwts->documentsFor($fetcher);
        $addressed = $documents->address($client, ResponseFormat::signed(null, ClientEncryption::registration()));
        $fetcher->failure = new ClientKeysUnavailableException('https://flaky.example/jwks cannot be reached.');

        // When
        $document = $documents->issue($client, $addressed, [
            'sub' => 'alice',
        ]);

        // Then
        static::assertSame(ClientEncryption::KEY_ID, ClientEncryption::open($document)['header']['kid']);
    }

    /**
     * Architecture §4.5
     */
    #[Test]
    public function aKmsThatDoesNotAnswerIsToldWhenTheDocumentIsAddressed(): void
    {
        // Given
        $client = Clients::public($this->tenant);
        $documents = $this->jwts->documentsFor(signer: $this->jwts->signerBehindAnOutage());

        // Then
        $this->expectException(KmsUnavailableException::class);
        $this->expectExceptionMessageIs('The sealed key could not be opened.');

        // When
        $documents->address($client, ResponseFormat::signed());
    }

    #[Test]
    public function aDocumentIsSignedWithTheKeyOpenedWhenItWasAddressed(): void
    {
        // Given
        $client = Clients::public($this->tenant);
        $addressed = $this->jwts->documents->address($client, ResponseFormat::signed());
        $documents = $this->jwts->documentsFor(signer: $this->jwts->signerBehindAnOutage());

        // When
        $document = $documents->issue($client, $addressed, [
            'sub' => 'alice',
        ]);

        // Then
        static::assertSame($this->jwts->key->kid, $this->jwts->verify($document, 'nobody', Fixtures::now(), [])['header']['kid']);
    }

    /**
     * RFC 7515 §4.1
     */
    #[Test]
    public function aSignedDocumentCarriesWhatItAddsToTheHeaderOfItsSignature(): void
    {
        // Given
        $client = Clients::public($this->tenant);
        $addressed = $this->jwts->documents->address($client, ResponseFormat::signed());

        // When
        $document = $this->jwts->documents->issue(
            $client,
            $addressed,
            [
                'sub' => 'alice',
            ],
            [
                'typ' => 'logout+jwt',
            ],
        );

        // Then
        static::assertSame('logout+jwt', $this->jwts->verify($document, 'nobody', Fixtures::now(), [])['header']['typ']);
    }

    /**
     * RFC 7516 §4.1, RFC 7519 §5.3
     */
    #[Test]
    public function anEncryptedDocumentCarriesWhatItAddsToTheHeaderOfItsEncryption(): void
    {
        // Given
        $client = Clients::encryptedFor($this->tenant);
        $addressed = $this->jwts->documents->address($client, ResponseFormat::signed(null, ClientEncryption::registration()));

        // When
        $document = $this->jwts->documents->issue(
            $client,
            $addressed,
            [
                'iss' => 'https://id.acme.example',
            ],
            [],
            [
                'iss' => 'https://id.acme.example',
            ],
        );

        // Then
        static::assertSame('https://id.acme.example', ClientEncryption::open($document)['header']['iss']);
    }

    /**
     * RFC 7519 §5.2
     */
    #[Test]
    public function aSignedThenEncryptedDocumentSaysItCarriesAJwtWhateverItAdds(): void
    {
        // Given
        $client = Clients::encryptedFor($this->tenant);
        $addressed = $this->jwts->documents->address($client, ResponseFormat::signed(null, ClientEncryption::registration()));

        // When
        $document = $this->jwts->documents->issue(
            $client,
            $addressed,
            [
                'sub' => 'alice',
            ],
            [],
            [
                'cty' => 'json',
            ],
        );

        // Then
        static::assertSame('JWT', ClientEncryption::open($document)['header']['cty']);
    }
}
