<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use DateTimeImmutable;
use App\Http\TotpProvisioningStore;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Credential\TotpSecret;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Event\CredentialRevoked;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\TotpAlgorithmInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use function array_unique;
use function intdiv;
use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\Attributes\Test;
use function serialize;
use function str_replace;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * Architecture §5.2
 */
final class AccountTwoFactorTest extends PasskeyTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    #[Test]
    public function thePageNeedsASessionOfTheCore(): void
    {
        // When
        $crawler = $this->browser->request('GET', '/account/two-factor');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertSame('login_required', $crawler->filter('p[data-error]')->attr('data-error'));
    }

    #[Test]
    public function thePageOffersToSetUpAnAppToAUserWithoutOne(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->twoFactorPage();

        // Then
        self::assertInteractionHeaders($this->browser->getResponse());
        static::assertCount(1, $crawler->filter('p[data-two-factor="none"]'));
        $form = $crawler->filter('form[data-two-factor="begin"]');
        static::assertSame('/account/two-factor/begin', $form->attr('action'));
        static::assertCount(1, $form->filter('input[name="_token"]'));
        static::assertCount(0, $crawler->filter('form[data-two-factor="revoke"]'));
    }

    #[Test]
    public function beginningShowsTheQrCodeTheKeyAndTheCodeForm(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $crawler = $this->begin();

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        self::assertInteractionHeaders($response);
        static::assertCount(1, $crawler->filter('figure[data-two-factor="qr-code"] svg'));
        static::assertCount(0, $crawler->filter('img'), 'No image is loaded from anywhere.');
        static::assertMatchesRegularExpression('/^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/', self::keyOf($crawler), 'A 160-bit secret in base32, in groups of four.');
        $form = $crawler->filter('form[data-two-factor="enrol"]');
        static::assertSame('/account/two-factor', $form->attr('action'));
        static::assertCount(1, $form->filter('input[name="code"]'));
        static::assertSame([], self::totpsOf($alice));
    }

    /**
     * Architecture §3.3, §5.2
     */
    #[Test]
    public function theProvisioningIsSealedInTheHttpSession(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $crawler = $this->begin();
        $key = str_replace(' ', '', self::keyOf($crawler));

        // When
        $stored = $this->readHttpSession()->get(TotpProvisioningStore::KEY);

        // Then
        static::assertIsArray($stored);
        $serialized = serialize($stored);
        static::assertStringNotContainsString($key, $serialized);
        static::assertStringNotContainsString(Base32::decodeUpper($key), $serialized);
        static::assertStringNotContainsString('otpauth://', $serialized);
    }

    #[Test]
    public function aWrongFirstCodeShowsTheSameQrCodeAgainAndCreatesNothing(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $key = self::keyOf($this->begin());

        // When
        $crawler = $this->submitFirstCode('000000');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('refused', $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertSame($key, self::keyOf($crawler));
        static::assertSame([], self::totpsOf($alice));
        static::assertSame([], self::events(CredentialEnrolled::class));
    }

    #[Test]
    public function theRightFirstCodeCreatesTheTotpAndShowsTheBackupCodes(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $secret = self::secretOf($this->begin());

        // When
        $crawler = $this->submitFirstCode(self::codeOf($secret, new DateTimeImmutable()));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertCount(1, $crawler->filter('p[data-two-factor="enrolled"]'));
        $codes = $crawler->filter('ol[data-two-factor="backup-codes"] li');
        static::assertCount(TotpCredential::BACKUP_CODES, $codes);
        static::assertMatchesRegularExpression('/^[A-Z2-7]{5}-[A-Z2-7]{5}$/', $codes->first()->text());
        $totps = self::totpsOf($alice);
        static::assertCount(1, $totps);
        static::assertFalse($totps[0]->isRevoked());
        static::assertCount(1, self::events(CredentialEnrolled::class));
        static::assertFalse($this->readHttpSession()->has(TotpProvisioningStore::KEY), 'The provisioning was not forgotten.');
    }

    #[Test]
    public function theBackupCodesAreShownOnlyOnce(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $secret = self::secretOf($this->begin());
        $this->submitFirstCode(self::codeOf($secret, new DateTimeImmutable()));

        // When
        $crawler = $this->twoFactorPage();

        // Then
        static::assertCount(0, $crawler->filter('ol[data-two-factor="backup-codes"]'));
        static::assertCount(0, $crawler->filter('p[data-two-factor="none"]'));
        static::assertSame((string) TotpCredential::BACKUP_CODES, $crawler->filter('p[data-backup-codes-left]')->attr('data-backup-codes-left'));
        static::assertCount(1, $crawler->filter('form[data-two-factor="revoke"]'));
    }

    #[Test]
    public function anEnrolmentAbandonedAtTheQrCodeLeavesNothing(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $this->begin();

        // When
        $crawler = $this->twoFactorPage();

        // Then
        static::assertCount(1, $crawler->filter('p[data-two-factor="none"]'));
        static::assertSame([], self::totpsOf($alice));
    }

    #[Test]
    public function aCodePostedWithoutAProvisioningIsRefused(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $token = $this->twoFactorPage()->filter('form[data-two-factor="begin"] input[name="_token"]')->attr('value');

        // When
        $crawler = $this->browser->request('POST', '/account/two-factor', [
            '_token' => $token,
            'code' => '000000',
        ]);

        // Then
        static::assertSame(
            Response::HTTP_FORBIDDEN,
            $this->browser->getResponse()->getStatusCode(),
            'The token of the begin form is not the token of the enrol form.',
        );
        static::assertSame('invalid_csrf_token', $crawler->filter('p[data-error]')->attr('data-error'));
    }

    #[Test]
    public function aCodePostedAfterTheProvisioningWasForgottenIsRefused(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $token = $this->begin()->filter('form[data-two-factor="enrol"] input[name="_token"]')->attr('value');
        $this->httpSession(static function (SessionInterface $httpSession): void {
            $httpSession->remove(TotpProvisioningStore::KEY);
        });

        // When
        $this->browser->request('POST', '/account/two-factor', [
            '_token' => $token,
            'code' => '000000',
        ]);

        // Then
        static::assertSame('no_provisioning', $this->afterTheForm()->filter('p[data-error]')->attr('data-error'));
    }

    #[Test]
    public function aSecondAppIsRefusedWhileOneIsActive(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $token = $this->twoFactorPage()->filter('form[data-two-factor="begin"] input[name="_token"]')->attr('value');
        $secret = self::secretOf($this->begin());
        $this->submitFirstCode(self::codeOf($secret, new DateTimeImmutable()));

        // When
        $this->browser->request('POST', '/account/two-factor/begin', [
            '_token' => $token,
        ]);

        // Then
        static::assertSame('already_enrolled', $this->afterTheForm()->filter('p[data-error]')->attr('data-error'));
    }

    #[Test]
    public function theEnrolmentInProgressIsAPageThatCanBeReadAgain(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $key = self::keyOf($this->begin());

        // When
        $again = $this->browser->request('GET', '/account/two-factor/enrol');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame($key, self::keyOf($again));
    }

    #[Test]
    public function theEnrolmentPageWithNothingDrawnSendsBackSayingSo(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/account/two-factor/enrol');

        // Then
        static::assertSame('no_provisioning', $this->afterTheForm()->filter('p[data-error]')->attr('data-error'));
    }

    #[Test]
    public function aBadFormTokenIsRefused(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->browser->request('POST', '/account/two-factor/begin', [
            '_token' => 'not the token',
        ]);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertSame('invalid_csrf_token', $crawler->filter('p[data-error]')->attr('data-error'));
    }

    /**
     * Architecture §5.2
     */
    #[Test]
    public function theAppIsRemovedFromThePage(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $secret = self::secretOf($this->begin());
        $this->submitFirstCode(self::codeOf($secret, new DateTimeImmutable()));

        // When
        $this->revoke();

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode());
        static::assertSame('/account/two-factor', $response->headers->get('Location'));
        $totps = self::totpsOf($alice);
        static::assertCount(1, $totps);
        static::assertTrue($totps[0]->isRevoked());
        static::assertCount(1, self::events(CredentialRevoked::class));
        static::assertCount(1, $this->twoFactorPage()->filter('p[data-two-factor="none"]'));
    }

    #[Test]
    public function thereIsNothingToRemoveOnceTheAppIsRemoved(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $secret = self::secretOf($this->begin());
        $this->submitFirstCode(self::codeOf($secret, new DateTimeImmutable()));
        $token = $this->twoFactorPage()->filter('form[data-two-factor="revoke"] input[name="_token"]')->attr('value');
        $this->revoke();

        // When
        $this->browser->request('POST', '/account/two-factor/revoke', [
            '_token' => $token,
        ]);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertCount(1, self::totpsOf($alice));
    }

    #[Test]
    public function aBackupCodeShownAtTheEnrolmentSignsTheUserInAfterThePassword(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        $secret = self::secretOf($this->begin());
        $backupCode = $this->submitFirstCode(self::codeOf($secret, new DateTimeImmutable()))->filter('ol[data-two-factor="backup-codes"] li')->eq(4)->text();
        $this->forgetTheBrowser();
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        static::assertSame('/login/code?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));

        // When
        $this->submitCode($interaction, $backupCode);

        // Then
        static::assertSame('/login?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertSame(['pwd', 'otp', 'mfa'], $this->boundSession()->methodReferences());
    }

    #[Test]
    public function thePasswordAloneSignsInAgainOnceTheAppIsRemoved(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        $secret = self::secretOf($this->begin());
        $this->submitFirstCode(self::codeOf($secret, new DateTimeImmutable()));
        $this->revoke();
        $this->forgetTheBrowser();
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertSame('/login?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertSame(['pwd'], $this->boundSession()->methodReferences());
    }

    /**
     * Architecture §5.2
     */
    #[Test]
    public function theBackupCodesAreDrawnAgainAndShownOnce(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $secret = self::secretOf($this->begin());
        $this->submitFirstCode(self::codeOf($secret, new DateTimeImmutable()));

        // When
        $crawler = $this->renewBackupCodes();

        // Then
        static::assertCount(TotpCredential::BACKUP_CODES, $crawler->filter('ol[data-two-factor="backup-codes"] code'));
        static::assertCount(1, $crawler->filter('p[data-two-factor="backup-codes-renewed"]'));
        static::assertCount(0, $this->twoFactorPage()->filter('ol[data-two-factor="backup-codes"]'));
    }

    #[Test]
    public function theCodesDrawnAgainReplaceTheOnesThatWereHeld(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $secret = self::secretOf($this->begin());
        $before = self::codesOf($this->submitFirstCode(self::codeOf($secret, new DateTimeImmutable())));

        // When
        $after = self::codesOf($this->renewBackupCodes());

        // Then
        static::assertCount(TotpCredential::BACKUP_CODES * 2, array_unique([...$before, ...$after]));
    }

    #[Test]
    public function aPersonWithoutASecondFactorHasNoCodesToDraw(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->twoFactorPage();

        // Then
        static::assertCount(0, $page->filter('form[data-two-factor="backup-codes"]'));
        static::assertCount(1, $page->filter('form[data-two-factor="begin"]'));
    }

    #[Test]
    public function drawingCodesWithoutTheTokenOfItsFormIsRefused(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('POST', '/account/two-factor/backup-codes', []);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Clipboard API §3
     */
    #[Test]
    public function theCodesAreOfferedToTheClipboardOfABrowserThatCanTakeThem(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $secret = self::secretOf($this->begin());

        // When
        $page = $this->submitFirstCode(self::codeOf($secret, new DateTimeImmutable()));

        // Then
        $button = $page->filter('button[data-copy="backup-codes"]');
        static::assertSame('backup-codes', $button->attr('data-copy'));
        static::assertSame('', $button->attr('hidden'));
        static::assertCount(1, $page->filter('ol#backup-codes[data-two-factor="backup-codes"]'));
    }

    /**
     * Clipboard API §3
     */
    #[Test]
    public function theKeyIsOfferedToTheClipboardOfABrowserThatCanTakeIt(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->begin();

        // Then
        $button = $page->filter('button[data-copy="two-factor-key"]');
        static::assertSame('two-factor-key', $button->attr('data-copy'));
        static::assertSame('', $button->attr('hidden'));
        static::assertCount(1, $page->filter('code#two-factor-key[data-two-factor="key"]'));
    }

    #[Test]
    public function theScriptThatCopiesIsServedByTheProvider(): void
    {
        // When
        $this->browser->request('GET', '/copy.js');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('text/javascript; charset=utf-8', $response->headers->get('Content-Type'));
    }

    private function renewBackupCodes(): Crawler
    {
        return $this->browser->submit($this->twoFactorPage()->selectButton('Generate new backup codes')->form());
    }

    /**
     * @return list<string>
     */
    private static function codesOf(Crawler $page): array
    {
        return $page->filter('ol[data-two-factor="backup-codes"] code')->each(
            static fn (Crawler $code): string => $code->text(),
        );
    }

    private function twoFactorPage(): Crawler
    {
        $crawler = $this->browser->request('GET', '/account/two-factor');
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    private function begin(): Crawler
    {
        $this->browser->submit($this->twoFactorPage()->selectButton('Set up an authenticator app')->form());

        return $this->afterTheForm();
    }

    private function submitFirstCode(string $code): Crawler
    {
        $form = $this->browser->getCrawler()->selectButton('Confirm')->form();
        $form['code'] = $code;
        $crawler = $this->browser->submit($form);

        return $this->browser->getResponse()->getStatusCode() === Response::HTTP_SEE_OTHER
            ? $this->browser->followRedirect()
            : $crawler;
    }

    private function revoke(): void
    {
        $this->browser->submit($this->twoFactorPage()->selectButton('Remove the authenticator app')->form());
    }

    private function submitLogin(string $interaction, string $username, string $password): void
    {
        $form = $this->loginPage($interaction)->selectButton('Sign in')->form();
        $form['_username'] = $username;
        $form['_password'] = $password;
        $this->browser->submit($form);
    }

    private function submitCode(string $interaction, string $code): void
    {
        $crawler = $this->browser->request('GET', '/login/code', [
            'interaction' => $interaction,
        ]);
        $form = $crawler->selectButton('Continue')->form();
        $form['_code'] = $code;
        $this->browser->submit($form);
    }

    private static function keyOf(Crawler $crawler): string
    {
        return $crawler->filter('code[data-two-factor="key"]')->text();
    }

    private static function secretOf(Crawler $crawler): TotpSecret
    {
        return new TotpSecret(Base32::decodeUpper(str_replace(' ', '', self::keyOf($crawler))));
    }

    private static function codeOf(TotpSecret $secret, DateTimeImmutable $at): string
    {
        return self::service('test.beffroi.totp_algorithm', TotpAlgorithmInterface::class)
            ->codeAt($secret, intdiv($at->getTimestamp(), TotpCredential::PERIOD));
    }

    /**
     * @return list<TotpCredential>
     */
    private static function totpsOf(User $user): array
    {
        self::reload();
        $managed = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');

        return self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($managed, TotpCredential::class);
    }
}
