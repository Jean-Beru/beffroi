<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Domain\Client\ResponseFormat;
use Heidi\Oidc\Exception\ClientKeysUnavailableException;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Tests\Fixture\ClientEncryption;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeClientJwksFetcher;
use Heidi\Oidc\Tests\Fixture\Jwts;
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
        $this->jwts->documents->issue($client, ResponseFormat::unsigned(), [
            'sub' => 'alice',
        ]);
    }

    /**
     * The registration of a client is checked when it is read, so a set that no longer holds a key the
     * document can be addressed to is a client that changed its keys since: it is said with the client and
     * the algorithm, and no document leaves.
     */
    #[Test]
    public function aClientWhosePublishedKeysNoLongerFitIsToldSoAndNothingLeaves(): void
    {
        // Given
        $client = Clients::withKeys($this->tenant, 'moved-on', jwksUri: new ClientUri('https://moved.example/jwks'));
        /** @var list<array<string, mixed>> $signingOnly */
        $signingOnly = [[
            ...ClientEncryption::privateKey()->toPublic()
                ->all(),
            'use' => 'sig',
        ]];
        $documents = $this->jwts->documentsFor(new FakeClientJwksFetcher([new ClientJwks($signingOnly)]));

        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIs('The client "moved-on" publishes no key a document encrypted under "ECDH-ES+A256KW" can be addressed to.');

        // When
        $documents->issue($client, ResponseFormat::signed(null, ClientEncryption::registration()), [
            'sub' => 'alice',
        ]);
    }
}
