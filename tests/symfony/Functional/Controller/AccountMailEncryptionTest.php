<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Tests\Symfony\Fixture\MailFixtures;
use Beffroi\Core\Application\Identity\MailEncryptionChoice;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0051: a person gives the certificate or the key the mail of the provider is encrypted to, beside their
 * verified address, and takes it back.
 */
final class AccountMailEncryptionTest extends BrowserTestCase
{
    #[Test]
    public function thePageNeedsASessionOfTheCore(): void
    {
        // When
        $this->browser->request('GET', '/account/mail-encryption');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aPersonWithNoVerifiedAddressIsOfferedNothingToEncryptTo(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->page();

        // Then
        static::assertSame([1, 0], [
            $page->filter('[data-mail-encryption="no-address"]')->count(),
            $page->filter('form[data-mail-encryption="give"]')->count(),
        ]);
    }

    #[Test]
    public function theCertificateAPersonGivesIsWhatTheirMailIsEncryptedTo(): void
    {
        // Given
        $alice = $this->verified();
        $this->signIn($alice);

        // When
        $this->give('smime', MailFixtures::read('person-certificate.pem'));

        // Then
        static::assertSame(Response::HTTP_SEE_OTHER, $this->browser->getResponse()->getStatusCode());
        static::assertSame('smime', self::personAgain($alice)->mailEncryption?->kind);
    }

    #[Test]
    public function theHistoryOfThePersonKeepsTheCertificateTheyGave(): void
    {
        // Given
        $alice = $this->verified();
        $this->signIn($alice);

        // When
        $this->give('smime', MailFixtures::read('person-certificate.pem'));

        // Then
        $changes = self::entityManager()->getRepository(ClaimChange::class)->findBy(['claim' => MailEncryptionChoice::CHANGED]);
        static::assertCount(1, $changes);
        static::assertStringStartsWith('smime ', (string) $changes[0]->became);
    }

    #[Test]
    public function aCertificateForAnotherAddressIsRefusedAndThePageSaysWhy(): void
    {
        // Given
        $alice = $this->verified();
        $this->signIn($alice);

        // When
        $this->give('smime', MailFixtures::read('person-elsewhere-certificate.pem'));

        // Then
        static::assertSame([1, null], [$this->page()->filter('[data-error="another_address"]')->count(), self::personAgain($alice)->mailEncryption]);
    }

    #[Test]
    public function aFormatThisDeploymentDoesNotWriteIsRefused(): void
    {
        // Given
        $alice = $this->verified();
        $this->signIn($alice);

        // When
        $this->give('elsewhere', MailFixtures::read('person-certificate.pem'));

        // Then
        static::assertSame([1, null], [$this->page()->filter('[data-error="unreadable"]')->count(), self::personAgain($alice)->mailEncryption]);
    }

    #[Test]
    public function thePageSaysWhatTheMailIsEncryptedTo(): void
    {
        // Given
        $alice = $this->verified();
        $this->signIn($alice);
        $this->give('smime', MailFixtures::read('person-certificate.pem'));

        // When
        $page = $this->page();

        // Then
        static::assertCount(1, $page->filter('[data-mail-encryption="smime"]'));
    }

    #[Test]
    public function aPersonTakesTheCertificateBack(): void
    {
        // Given
        $alice = $this->verified();
        $this->signIn($alice);
        $this->give('smime', MailFixtures::read('person-certificate.pem'));

        // When
        $this->browser->request('POST', '/account/mail-encryption/remove', ['_token' => $this->token()]);

        // Then
        static::assertNull(self::personAgain($alice)->mailEncryption);
    }

    #[Test]
    public function theProfileLeadsFromTheVerifiedAddressToThePage(): void
    {
        // Given
        $this->signIn($this->verified());

        // When
        $page = $this->browser->request('GET', '/account/profile');

        // Then
        static::assertSame('/account/mail-encryption', $page->filter('[data-claim="email"] a[data-mail-encryption-link]')->attr('href'));
    }

    private function verified(): User
    {
        $alice = self::user('alice');
        $alice->changeEmail(new EmailAddress('alice@acme.example'), true, self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($alice);

        return $alice;
    }

    private function page(): Crawler
    {
        $page = $this->browser->request('GET', '/account/mail-encryption');
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());

        return $page;
    }

    private function give(string $format, string $material): void
    {
        $this->browser->request('POST', '/account/mail-encryption', [
            '_token' => $this->token(),
            'format' => $format,
            'material' => $material,
        ]);
    }

    private function token(): string
    {
        return self::string($this->page()->filter('form[data-mail-encryption="give"] input[name="_token"]')->attr('value'));
    }
}
