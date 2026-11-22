<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Archive\ZipArchiveContainer;
use Beffroi\Core\Domain\Archive\ArchivePassword;
use Beffroi\Core\Domain\Archive\PersonalArchive;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Event\PersonDroppedTheirArchive;
use Beffroi\Core\Domain\Event\PersonTookTheirArchive;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Symfony\Component\Messenger\MessageBusInterface;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Credential\PasskeyUserHandle;
use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ActsOfAPersonInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PersonalArchiveRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use function file_put_contents;
use function sprintf;
use function str_repeat;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;
use ZipArchive;
use function array_column;
use function array_keys;
use const JSON_THROW_ON_ERROR;
use function json_decode;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

final class AccountArchiveTest extends BrowserTestCase
{
    private const string PASSPHRASE = 'correct horse battery staple';

    #[Test]
    public function aPersonWhoNeverAskedIsToldWhatAskingGivesThem(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->archivePage();

        // Then
        static::assertSame(['never'], $page->filter('p[data-archive]')->extract(['data-archive']));
        static::assertCount(1, $page->filter('form[data-archive-ask]'));
    }

    #[Test]
    public function thePageNamesWhatTheFileHolds(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->archivePage();

        // Then
        static::assertSame(
            ['profile', 'credentials', 'linked_identities', 'groups', 'consents', 'sessions', 'journal', 'changes', 'disclosures'],
            $page->filter('li[data-chapter]')->extract(['data-chapter']),
        );
    }

    /**
     * Architecture §5.7
     */
    #[Test]
    public function thePageSpeaksTheLanguageOfTheBrowser(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->browser->request('GET', '/account/archive', server: [
            'HTTP_ACCEPT_LANGUAGE' => 'fr-FR,fr;q=0.9',
        ]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));
        static::assertSame('fr', $page->filter('html')->attr('lang'));
        static::assertSame('Vos données', $page->filter('h1')->text());
        static::assertCount(9, $page->filter('li[data-chapter]'));
    }

    #[Test]
    public function askingBuildsTheArchiveAndThePageSaysItIsReady(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $page = $this->ask();

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame(['ready'], $page->filter('p[data-archive]')->extract(['data-archive']));
        static::assertCount(1, $page->filter('a[data-archive-file]'));
    }

    #[Test]
    public function anArchiveStillBeingBuiltSaysSo(): void
    {
        // Given
        $alice = self::user('alice');
        self::asked($alice);
        $this->signIn($alice);

        // When
        $page = $this->archivePage();

        // Then
        static::assertSame(['being_built'], $page->filter('p[data-archive]')->extract(['data-archive']));
        static::assertCount(0, $page->filter('a[data-archive-file]'));
        static::assertCount(0, $page->filter('form[data-archive-ask]'));
    }

    #[Test]
    public function anArchiveStillBeingBuiltOffersToDeleteTheRequest(): void
    {
        // Given
        $alice = self::user('alice');
        self::asked($alice);
        $this->signIn($alice);

        // When
        $page = $this->archivePage();

        // Then
        static::assertCount(1, $page->filter('form[data-archive-cancel]'));
    }

    #[Test]
    public function anArchiveWhoseBuildDidNotComeBackSaysSoAndOffersANewOne(): void
    {
        // Given
        $alice = self::user('alice');
        self::stalled($alice);
        $this->signIn($alice);

        // When
        $page = $this->archivePage();

        // Then
        static::assertSame(['stalled'], $page->filter('p[data-archive]')->extract(['data-archive']));
        static::assertCount(1, $page->filter('form[data-archive-ask]'));
    }

    #[Test]
    public function askingAgainOnceTheBuildDidNotComeBackBuildsTheFile(): void
    {
        // Given
        $alice = self::user('alice');
        self::stalled($alice);
        $this->signIn($alice);

        // When
        $page = $this->ask();

        // Then
        static::assertSame(['ready'], $page->filter('p[data-archive]')->extract(['data-archive']));
    }

    #[Test]
    public function askingAgainOnceTheBuildDidNotComeBackLeavesOneArchive(): void
    {
        // Given
        $alice = self::user('alice');
        $stalled = self::stalled($alice);
        $this->signIn($alice);

        // When
        $this->ask();

        // Then
        $latest = self::archives()->latestOf(self::reread($alice));
        static::assertNotNull($latest);
        static::assertFalse($latest->id->equals($stalled->id));
    }

    #[Test]
    public function anArchiveThatHasExpiredSaysSoAndOffersANewOne(): void
    {
        // Given
        $alice = self::user('alice');
        self::expired($alice);
        $this->signIn($alice);

        // When
        $page = $this->archivePage();

        // Then
        static::assertSame(['expired'], $page->filter('p[data-archive]')->extract(['data-archive']));
        static::assertCount(1, $page->filter('form[data-archive-ask]'));
    }

    #[Test]
    public function theFileIsTheDocumentOfEveryChapter(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->ask();

        // When
        $document = $this->file();

        // Then
        static::assertSame(
            ['archive', 'profile', 'credentials', 'linked_identities', 'groups', 'consents', 'sessions', 'journal', 'changes', 'disclosures'],
            array_keys($document),
        );
    }

    #[Test]
    public function theFileHoldsTheRecordAndTheJournalOfThePerson(): void
    {
        // Given
        $alice = self::user('alice');
        self::announce(new UserAuthenticated(self::session($alice, self::currentSecond())));
        $this->signIn($alice);
        $this->ask();

        // When
        $document = $this->file();

        // Then
        static::assertSame('alice', self::chapter($document, 'profile')[0]['username']);
        static::assertSame($alice->subject->value, self::chapter($document, 'profile')[0]['sub']);
        static::assertSame([UserAuthenticated::NAME], array_column(self::chapter($document, 'journal'), 'act'));
        static::assertNotSame([], self::chapter($document, 'sessions'));
    }

    /**
     * WebAuthn Level 3 §6.3.2
     */
    #[Test]
    public function theFileNamesAPasskeyByTheIdentifierItsColumnHolds(): void
    {
        // Given
        $alice = self::user('alice');
        $credentialId = "\x4a\xfb\xff\x00\x80";
        self::enrol($alice, $credentialId);
        $this->signIn($alice);
        $this->ask();

        // When
        $credentials = self::chapter($this->file(), 'credentials');

        // Then
        static::assertContains(Base64Url::encode($credentialId), array_column($credentials, 'external_id'));
    }

    #[Test]
    public function theFileIsServedAsJsonNamedAfterTheArchive(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $this->ask();

        // When
        $this->browser->request('GET', '/account/archive/file');
        $response = $this->browser->getResponse();

        // Then
        $archive = self::archives()->latestOf(self::reread($alice)) ?? static::fail('The archive was not stored.');
        $disposition = self::string($response->headers->get('Content-Disposition'));
        static::assertSame(PersonalArchive::MEDIA_TYPE, $response->headers->get('Content-Type'));
        static::assertStringStartsWith('attachment;', $disposition);
        static::assertStringContainsString($archive->fileName(), $disposition);
        static::assertStringNotContainsString('alice', $disposition);
    }

    #[Test]
    public function takingTheFileIsWrittenInTheJournal(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $this->ask();

        // When
        $this->browser->request('GET', '/account/archive/file');
        self::reload();

        // Then
        $acts = self::service('test.beffroi.acts', ActsOfAPersonInterface::class)->lastOf(self::reread($alice), [PersonTookTheirArchive::NAME], 10);
        static::assertCount(1, $acts);
    }

    #[Test]
    public function theArchiveOfSomebodyElseIsNotReachable(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $this->ask();
        $this->signIn(self::user('bob', 'bob-subject'));

        // When
        $this->browser->request('GET', '/account/archive/file');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function theFileOfAnArchiveThatHasExpiredIsNotGiven(): void
    {
        // Given
        $alice = self::user('alice');
        self::expired($alice);
        $this->signIn($alice);

        // When
        $this->browser->request('GET', '/account/archive/file');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aPersonWithNoArchiveReadyIsGivenNoFile(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/account/archive/file');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aBrowserWithNoSessionIsRefusedThePage(): void
    {
        // When
        $this->browser->request('GET', '/account/archive');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aBrowserWithNoSessionIsRefusedTheFile(): void
    {
        // When
        $this->browser->request('GET', '/account/archive/file');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function askingWithoutTheFormTokenIsRefused(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('POST', '/account/archive', []);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aReadyArchiveOffersTheFormThatWrapsIt(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->ask();

        // When
        $page = $this->archivePage();

        // Then
        static::assertSame(['zip'], $page->filter('form[data-archive-wrap]')->extract(['data-archive-wrap']));
        static::assertCount(1, $page->filter('a[data-archive-file]'));
    }

    #[Test]
    public function theFileLeavesWrappedUnderThePassphraseThatWasTyped(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $this->ask();

        // When
        $this->wrap(self::PASSPHRASE);
        $response = $this->browser->getResponse();

        // Then
        $archive = self::archives()->latestOf(self::reread($alice)) ?? static::fail('The archive was not stored.');
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame(ZipArchiveContainer::MEDIA_TYPE, $response->headers->get('Content-Type'));
        static::assertStringContainsString($archive->fileName('zip'), self::string($response->headers->get('Content-Disposition')));
        static::assertSame(
            self::string($archive->content),
            self::readFromZip(self::string($response->getContent()), $archive->fileName(), self::PASSPHRASE),
        );
    }

    #[Test]
    public function theWrappedFileCarriesNothingOfThePersonInTheClear(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->ask();

        // When
        $this->wrap(self::PASSPHRASE);

        // Then
        static::assertStringNotContainsString('alice', self::string($this->browser->getResponse()->getContent()));
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aPassphraseShorterThanTheFloorIsRefused(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->ask();

        // When
        $this->browser->request('POST', '/account/archive/file', [
            '_token' => $this->wrapToken(),
            'password' => str_repeat('a', ArchivePassword::MINIMUM_LENGTH - 1),
        ]);
        $page = $this->afterTheForm();

        // Then
        static::assertSame(['passphrase_refused'], $page->filter('p[data-error]')->extract(['data-error']));
    }

    #[Test]
    public function aPassphraseThatWasRefusedIsNotAnActOfTakingTheFile(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $this->ask();

        // When
        $this->browser->request('POST', '/account/archive/file', [
            '_token' => $this->wrapToken(),
            'password' => 'too short',
        ]);
        self::reload();

        // Then
        $acts = self::service('test.beffroi.acts', ActsOfAPersonInterface::class)->lastOf(self::reread($alice), [PersonTookTheirArchive::NAME], 10);
        static::assertSame([], $acts);
    }

    #[Test]
    public function aPersonWithNoArchiveReadyIsGivenNoWrappedFile(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $this->ask();
        $token = $this->wrapToken();
        self::archives()->forgetExpired(self::reread($alice)->tenant, self::currentSecond()->modify('+1 year'));
        self::reload();

        // When
        $this->browser->request('POST', '/account/archive/file', [
            '_token' => $token,
            'password' => self::PASSPHRASE,
        ]);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function wrappingWithoutTheFormTokenIsRefused(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->ask();

        // When
        $this->browser->request('POST', '/account/archive/file', [
            'password' => self::PASSPHRASE,
        ]);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
    }

    private static function announce(DomainEventInterface $event): void
    {
        self::service('event.bus', MessageBusInterface::class)->dispatch($event);
        self::reload();
    }

    #[Test]
    public function theFileIsDroppedWhenThePersonAsksForIt(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $this->ask();

        // When
        $this->drop();

        // Then
        static::assertNull(self::archives()->latestOf(self::reread($alice)));
    }

    #[Test]
    public function thePageOfAPersonWhoDroppedTheirFileSaysTheyHaveNone(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->ask();

        // When
        $page = $this->drop();

        // Then
        static::assertCount(1, $page->filter('p[data-archive="never"]'));
    }

    #[Test]
    public function droppingTheFileIsWrittenInTheJournal(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $this->ask();

        // When
        $this->drop();
        self::reload();

        // Then
        $acts = self::service('test.beffroi.acts', ActsOfAPersonInterface::class)->lastOf(self::reread($alice), [PersonDroppedTheirArchive::NAME], 10);
        static::assertCount(1, $acts);
    }

    #[Test]
    public function aPersonWithNoFileToDropIsToldThereWasNone(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->ask();
        $token = $this->dropToken();
        $this->drop($token);

        // When
        $page = $this->drop($token);

        // Then
        static::assertCount(1, $page->filter('p[data-error="nothing_to_drop"]'));
    }

    #[Test]
    public function aRequestStillBeingBuiltIsDroppedWhenThePersonAsksForIt(): void
    {
        // Given
        $alice = self::user('alice');
        self::asked($alice);
        $this->signIn($alice);

        // When
        $this->cancel();

        // Then
        static::assertNull(self::archives()->latestOf(self::reread($alice)));
    }

    #[Test]
    public function thePageOfAPersonWhoDroppedTheirRequestSaysTheyHaveNone(): void
    {
        // Given
        $alice = self::user('alice');
        self::asked($alice);
        $this->signIn($alice);

        // When
        $page = $this->cancel();

        // Then
        static::assertCount(1, $page->filter('p[data-archive="never"]'));
    }

    #[Test]
    public function droppingWithoutTheFormTokenIsRefused(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->ask();

        // When
        $this->browser->request('POST', '/account/archive/drop', []);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
    }

    private function ask(): Crawler
    {
        $token = self::string($this->archivePage()->filter('form[data-archive-ask] input[name="_token"]')->attr('value'));
        $this->browser->request('POST', '/account/archive', [
            '_token' => $token,
        ]);

        return $this->afterTheForm();
    }

    /**
     * @return array<string, mixed>
     */
    private function file(): array
    {
        $this->browser->request('GET', '/account/archive/file');
        $content = self::string($this->browser->getResponse()->getContent());
        $document = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
        static::assertIsArray($document);

        /** @var array<string, mixed> $document */
        return $document;
    }

    /**
     * @param array<string, mixed> $document
     *
     * @return list<array<string, mixed>>
     */
    private static function chapter(array $document, string $name): array
    {
        $chapter = $document[$name] ?? null;
        static::assertIsArray($chapter);

        /** @var list<array<string, mixed>> $chapter */
        return $chapter;
    }

    private function drop(?string $token = null): Crawler
    {
        $this->browser->request('POST', '/account/archive/drop', [
            '_token' => $token ?? $this->dropToken(),
        ]);

        return $this->afterTheForm();
    }

    private function dropToken(): string
    {
        return self::string($this->archivePage()->filter('form[data-archive-drop] input[name="_token"]')->attr('value'));
    }

    private function cancel(): Crawler
    {
        $token = self::string($this->archivePage()->filter('form[data-archive-cancel] input[name="_token"]')->attr('value'));
        $this->browser->request('POST', '/account/archive/drop', [
            '_token' => $token,
        ]);

        return $this->afterTheForm();
    }

    private function archivePage(): Crawler
    {
        $page = $this->browser->request('GET', '/account/archive');
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return $page;
    }

    private static function asked(User $user, ?string $document = null): PersonalArchive
    {
        $archive = PersonalArchive::asked(Uuid::v7(), self::reread($user), self::currentSecond());
        if ($document !== null) {
            $archive->fill($document, self::currentSecond());
        }
        self::archives()->save($archive);
        self::reload();

        return $archive;
    }

    private static function stalled(User $user): PersonalArchive
    {
        $archive = PersonalArchive::asked(
            Uuid::v7(),
            self::reread($user),
            self::currentSecond()->modify(sprintf('-%d minutes', PersonalArchive::BUILT_WITHIN_MINUTES + 1)),
        );
        self::archives()->save($archive);
        self::reload();

        return $archive;
    }

    private static function enrol(User $user, string $credentialId): void
    {
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->save(new PasskeyCredential(
                Uuid::v7(),
                self::reread($user),
                'YubiKey 5',
                $credentialId,
                'cose-public-key',
                0,
                ['usb'],
                false,
                false,
                Uuid::v4(),
                new PasskeyUserHandle(str_repeat("\x11", 64)),
                self::currentSecond(),
            ));
        self::reload();
    }

    private static function expired(User $user): PersonalArchive
    {
        $asked = self::currentSecond()->modify(sprintf('-%d days', PersonalArchive::KEPT_FOR_DAYS + 1));
        $archive = new PersonalArchive(
            Uuid::v7(),
            self::reread($user),
            $asked,
            $asked->modify(sprintf('+%d days', PersonalArchive::KEPT_FOR_DAYS)),
        );
        $archive->fill('{"profile":[]}', $asked);
        self::archives()->save($archive);
        self::reload();

        return $archive;
    }

    private function wrap(string $passphrase): void
    {
        $this->browser->request('POST', '/account/archive/file', [
            '_token' => $this->wrapToken(),
            'password' => $passphrase,
        ]);
    }

    private function wrapToken(): string
    {
        return self::string($this->archivePage()->filter('form[data-archive-wrap] input[name="_token"]')->attr('value'));
    }

    private static function readFromZip(string $wrapped, string $name, string $passphrase): string
    {
        $path = tempnam(sys_get_temp_dir(), 'beffroi-read-');
        if ($path === false) {
            static::fail('No temporary file could be opened.');
        }
        file_put_contents($path, $wrapped);

        try {
            $zip = new ZipArchive();
            static::assertTrue($zip->open($path));
            $zip->setPassword($passphrase);
            $read = $zip->getFromName($name);
            $zip->close();

            return $read === false ? static::fail('The passphrase did not open the file.') : $read;
        } finally {
            unlink($path);
        }
    }

    private static function reread(User $user): User
    {
        $reread = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id);
        static::assertInstanceOf(User::class, $reread);

        return $reread;
    }

    private static function archives(): PersonalArchiveRepositoryInterface
    {
        return self::service('test.beffroi.archives', PersonalArchiveRepositoryInterface::class);
    }
}
