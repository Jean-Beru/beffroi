<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client;

use Beffroi\Core\Domain\Tenant\Tenant;
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
 * What the provider hands one client, written once for the three documents that travel that way
 * (OIDC Core §3.1.3.7, §5.3.2, JARM §2.1): what the two steps refuse, and when.
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

    /**
     * A document a client registered neither a signature nor an encryption for is handed over as it is by
     * its caller, and asking for it here is a fault of the caller and not of the client.
     */
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

    /**
     * A shape that encrypts nothing goes to no key, so nothing the client publishes is read for it: a
     * client that publishes no key at all is addressed a signed document.
     */
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

    /**
     * The registration of a client is checked when it is read, so a set that no longer holds a key the
     * document can be addressed to is a client that changed its keys since: it is said with the client and
     * the algorithm when the document is addressed, and no document leaves.
     */
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
     * What the client publishes behind its "jwks_uri" is read when the document is addressed, so a set that
     * cannot be read right now is said then, before anything is struck.
     */
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

    /**
     * Striking a document reads nothing of the client (issue #836): one addressed while the keys of its
     * client could be read is struck for the key that was read, whatever the client serves by then.
     */
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
}
