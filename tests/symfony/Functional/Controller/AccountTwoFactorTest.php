<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use DateTimeImmutable;
use Beffroi\Bundle\Http\TotpProvisioningStore;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Credential\TotpSecret;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Event\CredentialRevoked;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\TotpAlgorithmInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use function intdiv;
use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\Attributes\Test;
use function serialize;
use function str_replace;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * The page of the second factor of the signed-in user (architecture §5.2): the enrolment of an
 * authenticator app by QR code through the enrolment of the core, the backup codes shown once, the
 * revocation, and what a login does with it. The authenticator app is the algorithm of the kernel, fed
 * with the key the page shows.
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

    /**
     * The enrolment page: the QR code drawn by the bundle as an SVG embedded in the page, the key for a
     * manual entry, the form of the first code; nothing in the rows yet.
     */
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
     * Architecture §3.3, §5.2: what the session store keeps of an enrolment in progress is sealed by the
     * KMS; neither the secret nor its base32 is in it.
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
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNPROCESSABLE_ENTITY, $response->getStatusCode());
        static::assertSame('refused', $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertSame($key, self::keyOf($crawler));
        static::assertSame([], self::totpsOf($alice));
        static::assertSame([], self::events(CredentialEnrolled::class));
    }

    /**
     * The acceptance of the issue: the first code verified before the credential exists, then the ten
     * backup codes shown, this once.
     */
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
        $codes = $crawler->filter('ul[data-two-factor="backup-codes"] li');
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
        static::assertCount(0, $crawler->filter('ul[data-two-factor="backup-codes"]'));
        static::assertCount(0, $crawler->filter('p[data-two-factor="none"]'));
        static::assertSame((string) TotpCredential::BACKUP_CODES, $crawler->filter('p[data-backup-codes-left]')->attr('data-backup-codes-left'));
        static::assertCount(1, $crawler->filter('form[data-two-factor="revoke"]'));
    }

    /**
     * The acceptance of the issue: an enrolment abandoned at the QR code leaves nothing.
     */
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
        $crawler = $this->browser->request('POST', '/account/two-factor', [
            '_token' => $token,
            'code' => '000000',
        ]);

        // Then
        static::assertSame(Response::HTTP_UNPROCESSABLE_ENTITY, $this->browser->getResponse()->getStatusCode());
        static::assertSame('no_provisioning', $crawler->filter('p[data-error]')->attr('data-error'));
    }

    /**
     * The form that begins is gone from the page once an app is active; posted anyway, with the token
     * the page gave before, it is refused.
     */
    #[Test]
    public function aSecondAppIsRefusedWhileOneIsActive(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $token = $this->twoFactorPage()->filter('form[data-two-factor="begin"] input[name="_token"]')->attr('value');
        $secret = self::secretOf($this->begin());
        $this->submitFirstCode(self::codeOf($secret, new DateTimeImmutable()));

        // When
        $crawler = $this->browser->request('POST', '/account/two-factor/begin', [
            '_token' => $token,
        ]);

        // Then
        static::assertSame(Response::HTTP_UNPROCESSABLE_ENTITY, $this->browser->getResponse()->getStatusCode());
        static::assertSame('already_enrolled', $crawler->filter('p[data-error]')->attr('data-error'));
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
     * Architecture §5.2: the app is removed from the page; the row stays, revoked, and is announced.
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
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/account/two-factor', $response->headers->get('Location'));
        $totps = self::totpsOf($alice);
        static::assertCount(1, $totps);
        static::assertTrue($totps[0]->isRevoked());
        static::assertCount(1, self::events(CredentialRevoked::class));
        static::assertCount(1, $this->twoFactorPage()->filter('p[data-two-factor="none"]'));
    }

    /**
     * Removed once, the app is not there to be removed again: the row stays revoked.
     */
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

    /**
     * End to end: the app set up on the page is what the login asks for, and a backup code the page
     * showed signs the user in.
     */
    #[Test]
    public function aBackupCodeShownAtTheEnrolmentSignsTheUserInAfterThePassword(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        $secret = self::secretOf($this->begin());
        $backupCode = $this->submitFirstCode(self::codeOf($secret, new DateTimeImmutable()))->filter('ul[data-two-factor="backup-codes"] li')->eq(4)->text();
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

    /**
     * Once the app is removed, the password alone signs the user in again.
     */
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

    private function twoFactorPage(): Crawler
    {
        $crawler = $this->browser->request('GET', '/account/two-factor');
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    /**
     * Clicks the button of the page that sets up an app: the enrolment page comes back.
     */
    private function begin(): Crawler
    {
        return $this->browser->submit($this->twoFactorPage()->selectButton('Set up an authenticator app')->form());
    }

    private function submitFirstCode(string $code): Crawler
    {
        $form = $this->browser->getCrawler()->selectButton('Confirm')->form();
        $form['code'] = $code;

        return $this->browser->submit($form);
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

    /**
     * The secret the page shows as a key, as an app takes it by hand.
     */
    private static function secretOf(Crawler $crawler): TotpSecret
    {
        return new TotpSecret(Base32::decodeUpper(str_replace(' ', '', self::keyOf($crawler))));
    }

    private static function codeOf(TotpSecret $secret, DateTimeImmutable $at): string
    {
        return self::service('test.beffroi.totp_algorithm', TotpAlgorithmInterface::class)->codeAt($secret, intdiv($at->getTimestamp(), TotpCredential::PERIOD));
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
