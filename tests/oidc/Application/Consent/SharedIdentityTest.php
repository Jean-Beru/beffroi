<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Consent;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Consent\SharedIdentity;
use Beffroi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Core §8, decision 0006
 */
final class SharedIdentityTest extends TestCase
{
    private User $alice;

    private InMemoryConsentRepository $consents;

    private SharedIdentity $sharedIdentity;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->consents = new InMemoryConsentRepository();
        $this->sharedIdentity = new SharedIdentity($this->consents);
    }

    #[Test]
    public function aClientDeclaredWithoutConsentIsToldWhoThePersonIs(): void
    {
        // Given
        $client = Clients::appliance($this->alice->tenant, new FakePasswordHasher()->hash(Clients::SECRET));

        // When / Then
        static::assertTrue($this->sharedIdentity->isSharedWith($this->alice, $client));
    }

    /**
     * OIDC Core §3.1.2.4
     */
    #[Test]
    public function aClientThePersonGaveAConsentIsToldWhoSheIs(): void
    {
        // Given
        $client = Clients::public($this->alice->tenant);
        $this->consents->save($this->consentTo($client));

        // When / Then
        static::assertTrue($this->sharedIdentity->isSharedWith($this->alice, $client));
    }

    #[Test]
    public function aClientThePersonNeverGaveAConsentIsToldNothing(): void
    {
        // Given
        $client = Clients::public($this->alice->tenant);

        // When / Then
        static::assertFalse($this->sharedIdentity->isSharedWith($this->alice, $client));
    }

    #[Test]
    public function aClientWhoseConsentThePersonRevokedIsToldNothing(): void
    {
        // Given
        $client = Clients::public($this->alice->tenant);
        $consent = $this->consentTo($client);
        $consent->revoke(Fixtures::now());
        $this->consents->save($consent);

        // When / Then
        static::assertFalse($this->sharedIdentity->isSharedWith($this->alice, $client));
    }

    #[Test]
    public function aConsentToAnotherClientTellsThisOneNothing(): void
    {
        // Given
        $client = Clients::public($this->alice->tenant);
        $this->consents->save($this->consentTo(Clients::public($this->alice->tenant, 'another-spa')));

        // When / Then
        static::assertFalse($this->sharedIdentity->isSharedWith($this->alice, $client));
    }

    private function consentTo(Client $client): Consent
    {
        return new Consent(Uuid::v7(), $this->alice, $client, new Scopes([Scope::openid()]), Fixtures::now());
    }
}
