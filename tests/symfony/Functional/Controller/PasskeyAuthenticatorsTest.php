<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Bridge\Webauthn\AuthenticatorList;
use Beffroi\Core\Bridge\Webauthn\MetadataAuthenticatorModels;
use Beffroi\Core\Port\AuthenticatorListStoreInterface;
use Beffroi\Core\Port\MetadataBlobStoreInterface;
use Beffroi\Core\Tests\Fixture\AuthenticatorImages;
use Beffroi\Core\Tests\Fixture\AuthenticatorLists;
use Beffroi\Core\Tests\Fixture\MetadataBlobs;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function str_repeat;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\Uid\Uuid;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;

final class PasskeyAuthenticatorsTest extends PasskeyTestCase
{
    private const string YUBIKEY = 'ee882879-721c-4913-9775-3dfcce97072a';

    private const string PROTON_PASS = '50726f74-6f6e-5061-7373-50726f746f6e';

    #[Test]
    public function aModelTheFidoMetadataNameIsShownWithItsLogoAndItsCertification(): void
    {
        // Given
        self::metadataNaming(self::YUBIKEY, 'YubiKey 5 Series', [AuthenticatorStatus::FIDO_CERTIFIED_L1]);
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, self::deviceOf(self::YUBIKEY));

        // When
        $cell = $this->authenticatorOf($passkey->id);

        // Then
        static::assertSame(MetadataAuthenticatorModels::SOURCE, $cell->attr('data-authenticator'));
        static::assertSame('YubiKey 5 Series', $cell->filter('span[data-model]')->text());
        static::assertSame([AuthenticatorImages::PNG], $cell->filter('img[data-logo=""]')->each(static fn (Crawler $image): ?string => $image->attr('src')));
        static::assertCount(1, $cell->filter('img'));
        static::assertSame('FIDO Certified, level 1', $cell->filter('span[data-certification="FIDO_CERTIFIED_L1"]')->text());
    }

    #[Test]
    public function aProviderTheListOfTheCommunityNamesIsShownWithTheLogoOfEachTheme(): void
    {
        // Given
        self::listNaming(self::PROTON_PASS, 'Proton Pass');
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, self::deviceOf(self::PROTON_PASS, synced: true));

        // When
        $cell = $this->authenticatorOf($passkey->id);

        // Then
        static::assertSame(AuthenticatorList::SOURCE, $cell->attr('data-authenticator'));
        static::assertSame('Proton Pass', $cell->filter('span[data-model]')->text());
        static::assertSame(AuthenticatorImages::SVG_LIGHT, $cell->filter('img[data-logo="light"]')->attr('src'));
        static::assertSame(AuthenticatorImages::SVG_DARK, $cell->filter('img[data-logo="dark"]')->attr('src'));
        static::assertCount(0, $cell->filter('span[data-certification]'));
    }

    #[Test]
    public function theFidoMetadataNameAModelBeforeTheListOfTheCommunity(): void
    {
        // Given
        self::metadataNaming(self::YUBIKEY, 'YubiKey 5 Series', [AuthenticatorStatus::FIDO_CERTIFIED_L1]);
        self::listNaming(self::YUBIKEY, 'Somebody else');
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, self::deviceOf(self::YUBIKEY));

        // When
        $cell = $this->authenticatorOf($passkey->id);

        // Then
        static::assertSame(MetadataAuthenticatorModels::SOURCE, $cell->attr('data-authenticator'));
        static::assertSame('YubiKey 5 Series', $cell->filter('span[data-model]')->text());
    }

    #[Test]
    public function aModelNoSourceNamesIsAnUnknownAuthenticator(): void
    {
        // Given
        self::listNaming(self::PROTON_PASS, 'Proton Pass');
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, self::device());

        // When
        $cell = $this->authenticatorOf($passkey->id);

        // Then
        static::assertSame('unknown', $cell->attr('data-authenticator'));
        static::assertSame('Unknown authenticator', $cell->filter('span[data-model]')->text());
        static::assertCount(0, $cell->filter('img'));
    }

    /**
     * WebAuthn Level 3 §18.1.1
     */
    #[Test]
    public function anAaguidOfZerosIsAnUnknownAuthenticatorWhateverTheListSays(): void
    {
        // Given
        self::listNaming('00000000-0000-0000-0000-000000000000', 'Anything');
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, new SoftwareAuthenticator(self::ORIGIN, aaguid: str_repeat("\0", 16)));

        // When
        $cell = $this->authenticatorOf($passkey->id);

        // Then
        static::assertSame('unknown', $cell->attr('data-authenticator'));
        static::assertSame('Unknown authenticator', $cell->filter('span[data-model]')->text());
    }

    /**
     * WebAuthn Level 3 §6.1.3
     */
    #[Test]
    #[DataProvider('provideBackupStates')]
    public function whetherThePasskeyIsSyncedIsSaidInWords(bool $backupEligible, bool $backedUp, string $state, string $words): void
    {
        // Given
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, new SoftwareAuthenticator(self::ORIGIN, backupEligible: $backupEligible, backedUp: $backedUp));

        // When
        $cell = $this->authenticatorOf($passkey->id);

        // Then
        static::assertSame($words, $cell->filter('span[data-backup="' . $state . '"]')->text());
    }

    /**
     * @return iterable<string, array{bool, bool, string, string}>
     */
    public static function provideBackupStates(): iterable
    {
        yield 'a single-device credential' => [false, false, 'single_device', 'Device-bound passkey'];
        yield 'a multi-device credential backed up' => [true, true, 'backed_up', 'Synced passkey, backed up'];
        yield 'a multi-device credential not backed up' => [true, false, 'not_backed_up', 'Synced passkey, not currently backed up'];
    }

    /**
     * WebAuthn Level 3 §5.8.4
     */
    #[Test]
    #[DataProvider('provideTransports')]
    public function howThePasskeyIsReachedIsSaidInWords(bool $synced, string $transports, string $words): void
    {
        // Given
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, self::device(synced: $synced));

        // When
        $cell = $this->authenticatorOf($passkey->id);

        // Then
        static::assertSame($words, $cell->filter('span[data-transports="' . $transports . '"]')->text());
    }

    /**
     * @return iterable<string, array{bool, string, string}>
     */
    public static function provideTransports(): iterable
    {
        yield 'a roaming authenticator over USB' => [false, 'usb', 'Reached through a security key over USB'];
        yield 'a platform authenticator' => [true, 'internal', 'Reached through its device'];
    }

    /**
     * WebAuthn Level 3 §6
     */
    #[Test]
    public function thePageSaysNothingVerifiesTheAuthenticatorItNames(): void
    {
        // Given
        $alice = self::user('alice');
        $this->enrol($alice, self::device());

        // When
        $crawler = $this->passkeysPage();

        // Then
        static::assertSame(
            'An authenticator is named after what it declared when the passkey was added: nothing verifies it.',
            $crawler->filter('p[data-authenticators-declared]')->text(),
        );
    }

    #[Test]
    public function aPageWithoutPasskeySaysNothingOfAuthenticators(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->passkeysPage();

        // Then
        static::assertCount(0, $crawler->filter('p[data-authenticators-declared]'));
    }

    #[Test]
    public function theAuthenticatorIsSaidInTheLanguageOfThePage(): void
    {
        // Given
        self::metadataNaming(self::YUBIKEY, 'YubiKey 5 Series', [AuthenticatorStatus::FIDO_CERTIFIED_L1]);
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, self::deviceOf(self::YUBIKEY));

        // When
        $crawler = $this->browser->request('GET', '/account/passkeys', server: [
            'HTTP_ACCEPT_LANGUAGE' => 'fr-FR,fr;q=0.9',
        ]);

        // Then
        $cell = $crawler->filter('tr[data-passkey="' . $passkey->id . '"] td[data-authenticator]');
        static::assertSame('Conservée par', $crawler->filter('thead th')->eq(1)->text());
        static::assertSame('YubiKey 5 Series', $cell->filter('span[data-model]')->text());
        static::assertSame('Certifié FIDO, niveau 1', $cell->filter('span[data-certification]')->text());
        static::assertSame('Passkey liée à son appareil', $cell->filter('span[data-backup]')->text());
        static::assertSame('Atteinte par une clé de sécurité en USB', $cell->filter('span[data-transports]')->text());
        static::assertSame(
            'Un authentificateur est nommé d’après ce qu’il a déclaré à l’ajout de la passkey : rien ne le vérifie.',
            $crawler->filter('p[data-authenticators-declared]')->text(),
        );
    }

    private function authenticatorOf(Uuid $passkey): Crawler
    {
        $cell = $this->passkeysPage()->filter('tr[data-passkey="' . $passkey . '"] td[data-authenticator]');
        static::assertCount(1, $cell);

        return $cell;
    }

    private static function deviceOf(string $aaguid, bool $synced = false): SoftwareAuthenticator
    {
        return new SoftwareAuthenticator(self::ORIGIN, backupEligible: $synced, backedUp: $synced, aaguid: Uuid::fromString($aaguid)->toBinary());
    }

    /**
     * @param list<string> $statuses
     */
    private static function metadataNaming(string $aaguid, string $description, array $statuses): void
    {
        self::service('test.beffroi.metadata_store', MetadataBlobStoreInterface::class)
            ->write(
                'mds-passkeys-page',
                MetadataBlobs::payload([MetadataBlobs::entry($aaguid, $statuses, $description, icon: AuthenticatorImages::PNG)]),
            );
    }

    private static function listNaming(string $aaguid, string $name): void
    {
        self::service('test.beffroi.authenticator_list_store', AuthenticatorListStoreInterface::class)
            ->write(
                AuthenticatorLists::document([$aaguid => AuthenticatorLists::model($name)]),
            );
    }
}
