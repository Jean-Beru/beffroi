<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Security;

use function array_map;
use App\Security\PasskeyCredentials;
use App\Security\PasskeyLogin;
use App\Security\PassportProofs;
use App\Security\PasswordLogin;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use App\Security\ProvingLoginInterface;
use App\Security\TotpCredentials;
use App\Security\TotpLogin;
use App\Security\VerifiedPassword;
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
            new PasswordLogin(),
            new PasskeyLogin(new InMemoryCredentialRepository(), new RecordingEventDispatcher()),
            new TotpLogin(),
        ]);
    }

    #[Test]
    public function aPasswordProvesAPassword(): void
    {
        // Given
        $passport = self::passport(new VerifiedPassword('secret'));

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
        $this->expectExceptionMessageIsOrContains('the passport carries the badge of no login of the provider');

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
        $methods = $this->proofs->provableMethods(Fixtures::tenant());

        // Then
        static::assertSame(['pwd', 'hwk', 'swk', 'user', 'mfa', 'otp'], self::values($methods));
    }

    /**
     * Issue #327: a tenant that signs its users in by passkey announces no password and no code, the floor
     * of its logins reading neither, and announces everything a passkey proves.
     */
    #[Test]
    public function aTenantAnnouncesNothingItsFloorForbids(): void
    {
        // When
        $methods = $this->proofs->provableMethods(Fixtures::hardenedTenant());

        // Then
        static::assertSame(['hwk', 'swk', 'user', 'mfa'], self::values($methods));
    }

    /**
     * Issue #327: the floor is asked of a login and not of a method, so a passkey that proves "user" and
     * "mfa" beside its key is admitted whole or not at all.
     */
    #[Test]
    public function aFloorNoWiredLoginProvesLeavesTheProviderWithNothingToAnnounce(): void
    {
        // Given
        $proofs = self::proofsOf([new PasswordLogin(), new TotpLogin()]);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('No login of the firewall of the interaction pages proves what the tenant "acme" requires of every login, "phishing_resistant".');

        // When
        $proofs->provableMethods(Fixtures::hardenedTenant());
    }

    /**
     * The point of reading the tagged logins: a firewall that offers the form login only announces a
     * password and nothing a passkey would prove.
     */
    #[Test]
    public function aFirewallThatOffersOneLoginAnnouncesThatOneOnly(): void
    {
        // Given
        $proofs = self::proofsOf([new PasswordLogin()]);

        // When
        $methods = $proofs->provableMethods(Fixtures::tenant());

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
        $proofs->provableMethods(Fixtures::tenant());
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
