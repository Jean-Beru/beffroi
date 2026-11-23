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
 * Decision 0010, decision 0006
 */
final class ATenantThatForbidsThePasswordTest extends PasskeyTestCase
{
    private const string USERNAME = 'alice';

    private const string PASSWORD = 'correct horse battery staple';

    /**
     * WebAuthn Level 3 §6.3.2.1
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
        static::assertStringContainsString('no authenticator app is needed', self::string($page->filter('p[data-two-factor="none"]')->text()));
    }

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
