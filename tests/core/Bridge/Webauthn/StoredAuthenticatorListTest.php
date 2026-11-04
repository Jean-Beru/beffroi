<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Webauthn;

use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticatorListStore;
use Beffroi\Core\Bridge\Webauthn\StoredAuthenticatorList;
use Beffroi\Core\Exception\AuthenticatorListRefusedException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Tests\Fixture\AuthenticatorLists;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class StoredAuthenticatorListTest extends TestCase
{
    private const string AAGUID = '9ddd1817-af5a-4672-a2b9-3e3dd95000a9';

    private InMemoryAuthenticatorListStore $store;

    private StoredAuthenticatorList $list;

    protected function setUp(): void
    {
        $this->store = new InMemoryAuthenticatorListStore();
        $this->list = new StoredAuthenticatorList($this->store);
    }

    #[Test]
    public function theStoredListNamesItsModels(): void
    {
        // Given
        $this->store->write(AuthenticatorLists::document([self::AAGUID => AuthenticatorLists::model('Windows Hello')]));

        // When / Then
        static::assertSame('Windows Hello', $this->list->model(Uuid::fromString(self::AAGUID))?->name);
    }

    #[Test]
    public function aProviderThatNeverStoredAListNamesNothingFromIt(): void
    {
        // When / Then
        static::assertNull($this->list->model(Uuid::fromString(self::AAGUID)));
    }

    #[Test]
    public function theListIsReadOnceForTheLifeOfTheProcess(): void
    {
        // Given
        $this->store->write(AuthenticatorLists::document([self::AAGUID => AuthenticatorLists::model('Windows Hello')]));
        $this->list->model(Uuid::fromString(self::AAGUID));
        $this->store->write(AuthenticatorLists::document([self::AAGUID => AuthenticatorLists::model('Another name')]));

        // When / Then
        static::assertSame('Windows Hello', $this->list->model(Uuid::fromString(self::AAGUID))?->name);
    }

    #[Test]
    public function aStoreThatHeldNothingIsNotAskedAgain(): void
    {
        // Given
        $this->list->model(Uuid::fromString(self::AAGUID));
        $this->store->write(AuthenticatorLists::document([self::AAGUID => AuthenticatorLists::model('Windows Hello')]));

        // When / Then
        static::assertNull($this->list->model(Uuid::fromString(self::AAGUID)));
    }

    #[Test]
    public function aStoredListThatDoesNotReadIsADefectOfTheStore(): void
    {
        // Given
        $this->store->write('{}');

        // When
        try {
            $this->list->model(Uuid::fromString(self::AAGUID));
            static::fail('A stored list that does not read was read.');
        } catch (RuntimeException $exception) {
            // Then
            static::assertSame(
                'The stored list of authenticators does not read: it names no authenticator, which is what a retired list becomes',
                $exception->getMessage(),
            );
            static::assertInstanceOf(AuthenticatorListRefusedException::class, $exception->getPrevious());
        }
    }
}
