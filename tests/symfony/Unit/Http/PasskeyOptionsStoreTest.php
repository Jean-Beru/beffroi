<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Http;

use Heidi\Bundle\Http\PasskeyOptionsStore;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Architecture §5.2: the options of a ceremony live in the HTTP session between the two requests it
 * takes, and are read once.
 */
final class PasskeyOptionsStoreTest extends TestCase
{
    private Session $session;

    private PasskeyOptionsStore $store;

    protected function setUp(): void
    {
        $this->session = new Session(new MockArraySessionStorage());
        $this->store = new PasskeyOptionsStore();
    }

    #[Test]
    public function theRequestOptionsAreReadOnce(): void
    {
        // Given
        $options = self::requestOptions();
        $this->store->storeRequest($this->session, $options);

        // When
        $first = $this->store->takeRequest($this->session);
        $second = $this->store->takeRequest($this->session);

        // Then
        static::assertSame($options, $first);
        static::assertNull($second);
    }

    #[Test]
    public function nothingIsReadWhenNothingWasStored(): void
    {
        // When / Then
        static::assertNull($this->store->takeRequest($this->session));
        static::assertNull($this->store->takeCreation($this->session, Uuid::v7()));
    }

    #[Test]
    public function theCreationOptionsAreReadOnceByTheUserTheyWereDrawnFor(): void
    {
        // Given
        $user = Uuid::v7();
        $options = self::creationOptions();
        $this->store->storeCreation($this->session, $user, $options);

        // When
        $first = $this->store->takeCreation($this->session, $user);
        $second = $this->store->takeCreation($this->session, $user);

        // Then
        static::assertSame($options, $first);
        static::assertNull($second);
    }

    #[Test]
    public function theCreationOptionsOfAnotherUserAreNotReadAndAreForgotten(): void
    {
        // Given
        $alice = Uuid::v7();
        $this->store->storeCreation($this->session, $alice, self::creationOptions());

        // When
        $byBob = $this->store->takeCreation($this->session, Uuid::v7());
        $byAlice = $this->store->takeCreation($this->session, $alice);

        // Then
        static::assertNull($byBob);
        static::assertNull($byAlice, 'A read by the wrong user spends the options.');
    }

    #[Test]
    public function aSessionValueTheStoreDidNotWriteIsNoOptions(): void
    {
        // Given
        $user = Uuid::v7();
        $this->session->set(PasskeyOptionsStore::REQUEST_KEY, 'not options');
        $this->session->set(PasskeyOptionsStore::CREATION_KEY, [
            'user' => $user->toRfc4122(),
            'options' => 'not options',
        ]);

        // When / Then
        static::assertNull($this->store->takeRequest($this->session));
        static::assertNull($this->store->takeCreation($this->session, $user));
    }

    private static function requestOptions(): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions::create(str_repeat('c', 32), 'op.test');
    }

    private static function creationOptions(): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(PublicKeyCredentialRpEntity::create('op.test', 'op.test'), PublicKeyCredentialUserEntity::create('alice', str_repeat('h', 64), 'alice'), str_repeat('c', 32));
    }
}
