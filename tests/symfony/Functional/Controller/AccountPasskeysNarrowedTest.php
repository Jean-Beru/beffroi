<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Http\PasskeysPage;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.2
 */
final class AccountPasskeysNarrowedTest extends PasskeyTestCase
{
    private const string YUBIKEY = 'cb69481e-8ff7-4039-93ec-0a2729a154a8';

    private const string PROTON_PASS = '50726f74-6f6e-5061-7373-50726f746f6e';

    #[Test]
    public function aRevokedPasskeyIsLeftOutOfThePageAsItOpens(): void
    {
        // Given
        $alice = self::user('alice');
        $kept = $this->enrol($alice, self::device(), 'kept');
        $this->revoke($this->enrol($alice, self::device(), 'revoked'));

        // When
        $page = $this->passkeysPage();

        // Then
        static::assertSame([(string) $kept->id], $page->filter('tbody tr[data-passkey]')->extract(['data-passkey']));
        static::assertCount(0, $page->filter('a[data-filter="clear"]'));
    }

    #[Test]
    #[DataProvider('provideStates')]
    public function theStateAskedForIsTheOneRead(string $state, string $revoked): void
    {
        // Given
        $alice = self::user('alice');
        $this->enrol($alice, self::device(), 'kept');
        $this->revoke($this->enrol($alice, self::device(), 'revoked'));

        // When
        $page = $this->passkeysPage([PasskeysPage::STATE => $state]);

        // Then
        static::assertSame([$revoked], $page->filter('tbody tr[data-passkey]')->extract(['data-revoked']));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideStates(): iterable
    {
        yield 'the revoked ones' => [PasskeysPage::REVOKED, 'yes'];
        yield 'a state the page does not offer' => ['lost', 'no'];
    }

    #[Test]
    public function theRevokedPasskeysComeAfterTheOthersWhenBothAreAskedFor(): void
    {
        // Given
        $alice = self::user('alice');
        $first = $this->enrol($alice, self::device(), 'first');
        $second = $this->enrol($alice, self::device(), 'second');
        $third = $this->enrol($alice, self::device(), 'third');
        $this->revoke($first);

        // When
        $page = $this->passkeysPage([PasskeysPage::STATE => PasskeysPage::EVERY_STATE]);

        // Then
        static::assertSame(
            [(string) $second->id, (string) $third->id, (string) $first->id],
            $page->filter('tbody tr[data-passkey]')->extract(['data-passkey']),
        );
    }

    /**
     * WebAuthn Level 3 §6.5.1
     */
    #[Test]
    public function theModelAskedForIsTheOnlyOneRead(): void
    {
        // Given
        $alice = self::user('alice');
        $yubikey = $this->enrol($alice, self::deviceOf(self::YUBIKEY));
        $this->enrol($alice, self::deviceOf(self::PROTON_PASS));

        // When
        $page = $this->passkeysPage([PasskeysPage::MODEL => self::YUBIKEY]);

        // Then
        static::assertSame([(string) $yubikey->id], $page->filter('tbody tr[data-passkey]')->extract(['data-passkey']));
        static::assertSame(self::YUBIKEY, $page->filter('select[name="authenticator"] option[selected]')->attr('value'));
    }

    /**
     * WebAuthn Level 3 §6.5.1
     */
    #[Test]
    public function theModelsOfferedAreThoseThePasskeysOfThePersonDeclare(): void
    {
        // Given
        $alice = self::user('alice');
        $this->enrol($alice, self::deviceOf(self::YUBIKEY));
        $this->enrol($alice, self::deviceOf(self::PROTON_PASS));
        $this->enrol($alice, self::deviceOf(self::YUBIKEY));

        // When
        $page = $this->passkeysPage();

        // Then
        static::assertSame(['', self::YUBIKEY, self::PROTON_PASS], $page->filter('select[name="authenticator"] option')->extract(['value']));
    }

    /**
     * WebAuthn Level 3 §6.1.3
     */
    #[Test]
    #[DataProvider('provideSynchronisations')]
    public function theSynchronisationAskedForIsTheOnlyOneRead(string $asked, string $backup): void
    {
        // Given
        $alice = self::user('alice');
        $this->enrol($alice, self::device(synced: true));
        $this->enrol($alice, self::device());

        // When
        $page = $this->passkeysPage([PasskeysPage::SYNC => $asked]);

        // Then
        static::assertSame([$backup], $page->filter('tbody tr[data-passkey] span[data-backup]')->extract(['data-backup']));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideSynchronisations(): iterable
    {
        yield 'the synced ones' => [PasskeysPage::SYNCED, 'backed_up'];
        yield 'the ones bound to their device' => [PasskeysPage::DEVICE_BOUND, 'single_device'];
    }

    /**
     * WebAuthn Level 3 §5.8.4
     */
    #[Test]
    public function theWayAskedForIsTheOnlyOneRead(): void
    {
        // Given
        $alice = self::user('alice');
        $this->enrol($alice, self::device(synced: true));
        $this->enrol($alice, self::device());

        // When
        $page = $this->passkeysPage([PasskeysPage::TRANSPORT => 'usb']);

        // Then
        static::assertSame(['usb'], $page->filter('tbody tr[data-passkey] span[data-transports]')->extract(['data-transports']));
    }

    #[Test]
    public function theDaysOfTheLastUseAreTheOnesRead(): void
    {
        // Given
        $alice = self::user('alice');
        $used = $this->enrol($alice, self::device());
        $this->enrol($alice, self::device());
        $this->use($used);

        // When
        $page = $this->passkeysPage([PasskeysPage::USED_FROM => self::currentSecond()->format('Y-m-d')]);

        // Then
        static::assertSame([(string) $used->id], $page->filter('tbody tr[data-passkey]')->extract(['data-passkey']));
        static::assertSame(self::currentSecond()->format('Y-m-d'), $page->filter('input[name="used_from"]')->attr('value'));
    }

    #[Test]
    public function aPageNarrowedToNothingSaysSoAndOffersTheWayBack(): void
    {
        // Given
        $this->enrol(self::user('alice'), self::device());

        // When
        $page = $this->passkeysPage([PasskeysPage::SYNC => PasskeysPage::SYNCED]);

        // Then
        static::assertSame('No passkey matches the filters.', $page->filter('tbody tr[data-empty]')->text());
        static::assertSame('/account/passkeys', $page->filter('a[data-filter="clear"]')->attr('href'));
    }

    private function revoke(PasskeyCredential $passkey): void
    {
        $passkey = self::reread($passkey);
        $passkey->revoke(self::currentSecond());
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->save($passkey);
        self::reload();
    }

    private function use(PasskeyCredential $passkey): void
    {
        $passkey = self::reread($passkey);
        $passkey->recordUse(Fixtures::authenticatorData(signCount: 1), self::currentSecond());
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->save($passkey);
        self::reload();
    }

    private static function reread(PasskeyCredential $passkey): PasskeyCredential
    {
        self::reload();
        $reread = self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->find($passkey->id);
        static::assertInstanceOf(PasskeyCredential::class, $reread);

        return $reread;
    }

    private static function deviceOf(string $aaguid): SoftwareAuthenticator
    {
        return new SoftwareAuthenticator(self::ORIGIN, aaguid: Uuid::fromString($aaguid)->toBinary());
    }
}
