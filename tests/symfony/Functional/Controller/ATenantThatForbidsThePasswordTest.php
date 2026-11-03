<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\CredentialForgotten;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Session\PhishingResistant;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #327: a tenant signs its users in by passkey and forbids the password. What the tenant names is
 * one predicate of the provider as the floor of its logins (decision 0010), and everything else is read
 * off it: the page offers what the floor admits, the core refuses what it does not, and the credentials it
 * forbids are not left in the store.
 *
 * The page hiding a form is not the refusal, which is why both halves are here: the check path of the
 * firewall stays postable, and a password posted to it is refused by the core as the page not offering it
 * would suggest (decision 0006, one flat message).
 */
final class ATenantThatForbidsThePasswordTest extends PasskeyTestCase
{
    private const string USERNAME = 'alice';

    private const string PASSWORD = 'correct horse battery staple';

    /**
     * The page of such a tenant has nothing to type: no password, and no username either, a passkey being
     * signed by a discoverable credential that names its own user (WebAuthn Level 3 §6.3.2.1).
     */
    #[Test]
    public function theLoginPageOffersThePasskeyAndNothingToType(): void
    {
        // Given
        self::userWithPassword(self::USERNAME, self::PASSWORD);
        self::harden(new PhishingResistant());
        self::reload();

        // When
        $page = $this->loginPage($this->authorize());

        // Then
        static::assertCount(0, $page->filter('input[name="_password"]'));
        static::assertCount(0, $page->filter('input[name="_username"]'));
        static::assertCount(1, $page->filter('form[data-passkey="login"]'));
        static::assertCount(1, $page->filter('p[data-only="passkey"]'));
    }

    /**
     * A tenant that has not hardened is the tenant this provider always served: both forms, and the
     * username to type the password against.
     */
    #[Test]
    public function aTenantThatNamedNoFloorOffersBoth(): void
    {
        // Given
        self::userWithPassword(self::USERNAME, self::PASSWORD);
        self::reload();

        // When
        $page = $this->loginPage($this->authorize());

        // Then
        static::assertCount(1, $page->filter('input[name="_password"]'));
        static::assertCount(1, $page->filter('input[name="_username"]'));
        static::assertCount(1, $page->filter('form[data-passkey="login"]'));
        static::assertCount(0, $page->filter('p[data-only="passkey"]'));
    }

    /**
     * The same derivation on the page of the account: a tenant that signs its users in by passkey does not
     * offer a second factor it would refuse to enrol, and the page says why rather than holding a button
     * that always fails.
     */
    #[Test]
    public function theAccountOffersNoSecondFactorSuchATenantWouldRefuse(): void
    {
        // Given
        $this->signIn(self::userWithPassword(self::USERNAME, self::PASSWORD));
        self::harden(new PhishingResistant());
        self::reload();

        // When
        $page = $this->browser->request('GET', '/account/two-factor');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertCount(0, $page->filter('form[data-two-factor="begin"]'));
        static::assertStringContainsString('needs no authenticator app', self::string($page->filter('p[data-two-factor="none"]')->text()));
    }

    /**
     * The check path is still there and still reads a form: what refuses is the core, and it refuses
     * before naming anybody, which is why the reason is the floor and not an account that holds no
     * password any more.
     */
    #[Test]
    public function thePasswordThatWasRightIsRefusedByTheFloor(): void
    {
        // Given
        self::userWithPassword(self::USERNAME, self::PASSWORD);
        self::harden(new PhishingResistant());
        self::reload();
        $interaction = $this->authorize();
        $token = $this->loginPage($interaction)->filter('form[data-passkey="login"] input[name="_csrf_token"]')->attr('value');
        static::assertIsString($token);
        self::forgetEvents();

        // When
        $this->browser->request('POST', '/login?interaction=' . $interaction, [
            '_username' => self::USERNAME,
            '_password' => self::PASSWORD,
            '_csrf_token' => $token,
        ]);

        // Then
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertSame(AuthenticationFailureReason::BelowTheFloor, self::events(AuthenticationFailed::class)[0]->reason ?? null);
        static::assertSame([], self::events(UserAuthenticated::class));
        static::assertFalse($this->isBoundToASession());
    }

    /**
     * What the floor forbids is not left dormant in the store: the row of the password goes, and the act
     * is written in the journal of that person, which is the only trace that remains of it.
     */
    #[Test]
    public function thePasswordOfItsUsersIsForgottenWhenTheTenantHardens(): void
    {
        // Given
        $alice = self::userWithPassword(self::USERNAME, self::PASSWORD);
        self::forgetEvents();

        // When
        $forgotten = self::harden(new PhishingResistant());

        // Then
        static::assertSame(1, $forgotten);
        static::assertSame([], self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($alice, PasswordCredential::class));
        static::assertCount(1, self::events(CredentialForgotten::class));
    }

    /**
     * And the way in the tenant kept still works: the passkey proves the possession of a key, which is
     * what its floor reads, so the session opens (SessionOpener).
     */
    #[Test]
    public function thePasskeyStillSignsThePersonIn(): void
    {
        // Given
        $device = self::device();
        $this->enrol(self::userWithPassword(self::USERNAME, self::PASSWORD), $device);
        $this->forgetTheBrowser();
        self::harden(new PhishingResistant());
        self::reload();
        self::forgetEvents();

        // When
        $this->loginWithPasskey($this->authorize(), $device);

        // Then
        static::assertCount(1, self::events(UserAuthenticated::class));
        static::assertSame([], self::events(AuthenticationFailed::class));
        static::assertTrue($this->isBoundToASession());
    }
}
