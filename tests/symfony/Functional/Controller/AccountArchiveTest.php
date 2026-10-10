<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Bundle\Archive\ZipArchiveContainer;
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

/**
 * Issue #453, RGPD articles 15 and 20: a person asks for everything this provider holds about them in one
 * click, the archive is built off that request, and they download it once it is ready.
 *
 * The buses are synchronous in this suite, so what the browser comes back to is a file already built;
 * what a deployment sees between the two is the state the page says it is in, which the tests below play
 * by writing a row and not building it.
 */
final class AccountArchiveTest extends BrowserTestCase
{
    /**
     * What a person types to have their file leave under it (issue #483), several words as the page asks.
     */
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

    /**
     * What the file holds is read from the chapters that are wired, so a kind of fact this provider comes
     * to hold about a person is named on the page by being wired.
     */
    #[Test]
    public function thePageNamesWhatTheFileHolds(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->archivePage();

        // Then
        static::assertSame(
            ['profile', 'credentials', 'linked_identities', 'groups', 'consents', 'sessions', 'journal', 'changes'],
            $page->filter('li[data-chapter]')->extract(['data-chapter']),
        );
    }

    /**
     * Architecture §5.7: every word a person reads comes from the catalogue of their language, a word the
     * catalogue lacks failing this kernel. So a chapter wired without a label of its own is red here, in
     * both languages the bundle ships, and never a key shown to a person.
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
        static::assertCount(8, $page->filter('li[data-chapter]'));
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

    /**
     * The archive still being built says so rather than giving nothing, which is the one answer a page
     * like this may not give.
     */
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

    /**
     * A request a person can take back while it is being built: one they changed their mind about, and
     * one whose build never came back, are one row and one thing to say about it.
     */
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

    /**
     * Nothing comes back to say a build threw, so a row past the delay a build is given is a row this
     * provider says it is not building: the page says that rather than a week of "being built", and the
     * button that asks for a file is back.
     */
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

    /**
     * The row a build never filled holds nothing and nothing will fill it, so asking again takes it away
     * rather than leaving a person with two.
     */
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
            ['archive', 'profile', 'credentials', 'linked_identities', 'groups', 'consents', 'sessions', 'journal', 'changes'],
            array_keys($document),
        );
    }

    /**
     * The whole point of the file: what every page of the account shows separately, read in one place, the
     * journal of their own acts included.
     */
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
     * The file name travels in a header that proxies and browsers write down, so it names the archive and
     * never the person.
     */
    /**
     * A credential ID is what the authenticator issued (WebAuthn Level 3 §6.3.2), octets and not text, and
     * a document is JSON: the file names it in the alphabet the column holding it uses, and a person who
     * signs in by passkey is not a person whose archive cannot be built.
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

    /**
     * The act that matters most of the three: a file holding everything this provider knows of somebody
     * left it, and the journal says so.
     */
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

    /**
     * The route carries no identifier, so the archive of somebody else is not refused here, it is not
     * reachable from here.
     */
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

    /**
     * The file of an archive past its date is nothing, whether or not the timed step that forgets the row
     * has come round yet.
     */
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

    /**
     * Issue #483: a file that is ready leaves in one of two forms, and which container the other one is is
     * read from what is wired rather than named on the page.
     */
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

    /**
     * The one file where everything this provider knows of somebody stands in clear at once leaves saying
     * nothing of them to whoever ends up holding it.
     */
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
     * The floor is refused and not warned about (decision 0006), and the page says it was refused without
     * saying what was typed nor how far off it was.
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

    /**
     * A passphrase that is refused takes nothing with it: it is judged before the archive is asked for, so
     * nothing left and the journal does not say it did.
     */
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
        // the row forgotten the way the timed step forgets it once the file has expired, the form of the
        // page this person still holds naming a file that is not there any more
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

    /**
     * Issue #453: the file they have is a file this provider stops holding when they say so, before the
     * date it would have gone away on by itself.
     */
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

    /**
     * The row is gone, so the page says again what asking for a file would give them.
     */
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

    /**
     * The identifier is all that is left of the archive once the row is gone, which is why the act is
     * written where what became of the request is read.
     */
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

    /**
     * A person whose file went away under them, or who clicked twice, is told there was none rather than
     * shown a page that says nothing happened (issue #481).
     */
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

    /**
     * The one state a page may not leave somebody in is a state with no way out: a build that threw would
     * otherwise hold a person for the week the row is kept.
     */
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

    /**
     * Asking answers with a redirection (issue #481), so what this reads is the page it comes back to.
     */
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
     * One chapter of the document, narrowed where it is read: what comes back from a decoded file is a
     * shape nothing declares, and a test that asserts on it says what it expected to find.
     *
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

    /**
     * Dropping the file answers with a redirection too (issue #481), so what this reads is the page it
     * comes back to. The token is the one the page renders, and a caller that already holds it says so:
     * a page offering no file to drop renders no form to read one from.
     */
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

    /**
     * The same route, reached from the form a request that is not built yet renders: what the person takes
     * back there is the request and not a file they hold.
     */
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

    /**
     * A row written straight into the store, which is how the two states a synchronous suite never sees
     * are played: the person is reread first, a row hanging off a person the manager does not hold being
     * a row it would try to write again.
     *
     * @param string|null $document what the archive was built with, null for one still being built
     */
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

    /**
     * A row asked for past the delay a build is given and never filled, which is what a build that threw
     * leaves behind. Its date is in the past rather than the clock being moved, for the reason the row
     * below gives.
     */
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

    /**
     * A passkey written straight into the store, the credential ID being what this reads the document for:
     * what a browser enrols is played where enrolment is the subject (AccountPasskeysTest).
     */
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

    /**
     * An archive built and past the date it goes away on. Its dates are in the past rather than the clock
     * being moved: a week forward is a week past the session of the browser reading the page, and what
     * this plays is an archive that expired and not a person who has to sign in again.
     */
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

    /**
     * The wrapped file asked for the way a browser asks for it, by the form of the page.
     */
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

    /**
     * The entry read back the way whoever downloaded the file reads it, by a tool that knows the format and
     * the passphrase.
     */
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
