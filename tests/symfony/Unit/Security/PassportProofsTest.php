<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Security;

use function array_map;
use Beffroi\Bundle\Security\PasskeyCredentials;
use Beffroi\Bundle\Security\PasskeyLogin;
use Beffroi\Bundle\Security\PassportProofs;
use Beffroi\Bundle\Security\DatedPasswordCredential;
use Beffroi\Bundle\Security\PasswordLogin;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Bundle\Security\ProvingLoginInterface;
use Beffroi\Bundle\Security\TotpCredentials;
use Beffroi\Bundle\Security\TotpLogin;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Credential\VerifiedPasskeyAssertion;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\PendingLogin;
use Beffroi\Core\Tests\Fixture\Fixtures;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CredentialsInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * Decision 0010 and architecture §5.4: what the logins of the firewall prove is read from the logins
 * that are tagged, both for the session that is opened and for what the discovery announces.
 */
final class PassportProofsTest extends TestCase
{
    private PassportProofs $proofs;

    protected function setUp(): void
    {
        $this->proofs = self::proofsOf([
            self::passwordLogin(),
            new PasskeyLogin(new InMemoryCredentialRepository(), new RecordingEventDispatcher()),
            new TotpLogin(self::passwords()),
        ]);
    }

    #[Test]
    public function aPasswordProvesAPassword(): void
    {
        // Given
        $passport = self::passport(new PasswordCredentials('secret'));

        // When
        $methods = $this->proofs->methods($passport);

        // Then
        static::assertSame(['pwd'], self::values($methods));
    }

    /**
     * WebAuthn Level 3 §6.1: the flags of the assertion, not what the passkey could prove.
     */
    #[Test]
    public function aPasskeyProvesWhatTheFlagsOfItsAssertionSay(): void
    {
        // Given
        $assertion = new VerifiedPasskeyAssertion(Fixtures::passkey(), Fixtures::authenticatorData(userVerified: true));
        $passport = self::passport(new PasskeyCredentials($assertion));

        // When
        $methods = $this->proofs->methods($passport);

        // Then
        static::assertSame(['hwk', 'user', 'mfa'], self::values($methods));
    }

    /**
     * Architecture §5.4: the session is opened only at the second step, so the badge carries both.
     */
    #[Test]
    public function aCodeProvesWhatTheFirstStepProvedAndTheCode(): void
    {
        // Given
        $login = PendingLogin::provenAt(Fixtures::user()->id, [AuthenticationMethod::password()], Fixtures::now());
        $passport = self::passport(new TotpCredentials($login, TotpCredential::method()));

        // When
        $methods = $this->proofs->methods($passport);

        // Then
        static::assertSame(['pwd', 'otp'], self::values($methods));
    }

    #[Test]
    public function aPassportNoLoginRecognisesIsRefusedLoudly(): void
    {
        // Given
        $passport = new SelfValidatingPassport(new UserBadge('alice'));

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('the passport carries the badge of no login of the bundle');

        // When
        $this->proofs->methods($passport);
    }

    /**
     * Decision 0010: "acr_values_supported" is derived from this list.
     */
    #[Test]
    public function whatIsAnnouncedIsEveryMethodOfTheTaggedLoginsEachOnce(): void
    {
        // When
        $methods = $this->proofs->provableMethods();

        // Then
        static::assertSame(['pwd', 'hwk', 'swk', 'user', 'mfa', 'otp'], self::values($methods));
    }

    /**
     * The point of reading the tagged logins: a firewall that offers the form login only announces a
     * password and nothing a passkey would prove.
     */
    #[Test]
    public function aFirewallThatOffersOneLoginAnnouncesThatOneOnly(): void
    {
        // Given
        $proofs = self::proofsOf([self::passwordLogin()]);

        // When
        $methods = $proofs->provableMethods();

        // Then
        static::assertSame(['pwd'], self::values($methods));
    }

    #[Test]
    public function aFirewallWithoutALoginAnnouncesNothingAndSaysSo(): void
    {
        // Given
        $proofs = self::proofsOf([]);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The firewall of the interaction pages offers at least one login.');

        // When
        $proofs->provableMethods();
    }

    private static function passwords(): DatedPasswordCredential
    {
        return new DatedPasswordCredential(new InMemoryCredentialRepository());
    }

    private static function passwordLogin(): PasswordLogin
    {
        return new PasswordLogin(self::passwords());
    }

    /**
     * @param list<ProvingLoginInterface> $logins
     */
    private static function proofsOf(array $logins): PassportProofs
    {
        return new PassportProofs($logins);
    }

    private static function passport(CredentialsInterface $credentials): Passport
    {
        return new Passport(new UserBadge('alice'), $credentials);
    }

    /**
     * @param list<AuthenticationMethod> $methods
     *
     * @return list<string>
     */
    private static function values(array $methods): array
    {
        return array_map(static fn (AuthenticationMethod $method): string => $method->value, $methods);
    }
}
