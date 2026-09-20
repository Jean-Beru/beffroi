<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Interaction;

use function array_map;
use Heidi\Core\Domain\Credential\Credential;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Totps;
use Heidi\Oidc\Domain\Interaction\StepUp;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0010, architecture §4.3: a step-up is decided on what this user can still prove, credential by
 * credential, against the requested classes the provider can prove.
 */
final class StepUpTest extends TestCase
{
    private User $alice;

    private AuthenticationProofs $password;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->password = AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now());
    }

    /**
     * A passkey of the user, added to a password session, reaches "phr": the step-up names the class and
     * the passkey, not the password, which adds nothing to what the session has.
     */
    #[Test]
    public function aCredentialWhoseMethodsWithTheProofsSatisfyAClassMakesTheStepUp(): void
    {
        // Given
        $passkey = Fixtures::passkey($this->alice);

        // When
        $stepUp = StepUp::towards($this->password, [AuthenticationContextClass::phishingResistant()], [Fixtures::password($this->alice), $passkey]);

        // Then
        static::assertNotNull($stepUp);
        static::assertSame($this->password, $stepUp->proofs);
        static::assertSame(['phr'], self::names($stepUp->classes));
        static::assertSame([$passkey], $stepUp->credentials);
    }

    /**
     * No credential of the user reaches any requested class: nothing to step up to, the caller refuses
     * or answers with what the session has.
     */
    #[Test]
    public function thereIsNoStepUpWhenNoCredentialOfTheUserReachesAClass(): void
    {
        // When / Then
        static::assertNull(StepUp::towards($this->password, [AuthenticationContextClass::phishingResistant()], [Fixtures::password($this->alice)]));
    }

    /**
     * The session satisfies a requested class already: there is nothing to step up to, whatever the user holds.
     */
    #[Test]
    public function thereIsNoStepUpWhenTheProofsSatisfyARequestedClassAlready(): void
    {
        // Given
        $proofs = AuthenticationProofs::ofAll([AuthenticationMethod::password(), new AuthenticationMethod('otp')], Fixtures::now());

        // When / Then
        static::assertNull(StepUp::towards($proofs, [AuthenticationContextClass::twoFactors()], [Fixtures::passkey($this->alice)]));
    }

    /**
     * A revoked credential authenticates nobody: it counts for nothing, and hides nothing enrolled after it.
     */
    #[Test]
    public function aRevokedCredentialCountsForNothing(): void
    {
        // Given
        $revoked = Fixtures::passkey($this->alice, 'Lost key', 'lost');
        $revoked->revoke(Fixtures::now());
        $passkey = Fixtures::passkey($this->alice);

        // When
        $stepUp = StepUp::towards($this->password, [AuthenticationContextClass::phishingResistant()], [$revoked, $passkey]);

        // Then
        static::assertNotNull($stepUp);
        static::assertSame([$passkey], $stepUp->credentials);
    }

    /**
     * A credential of a kind that declares no method counts for nothing either, and hides nothing after it.
     */
    #[Test]
    public function aCredentialThatDeclaresNoMethodCountsForNothing(): void
    {
        // Given
        $credential = new class(Fixtures::user()) extends Credential {
            public function __construct(User $user)
            {
                parent::__construct(Uuid::v7(), $user, Fixtures::now());
            }

            public function kind(): string
            {
                return 'recovery';
            }
        };
        $passkey = Fixtures::passkey($this->alice);

        // When
        $stepUp = StepUp::towards($this->password, [AuthenticationContextClass::phishingResistant()], [$credential, $passkey]);

        // Then
        static::assertNotNull($stepUp);
        static::assertSame([$passkey], $stepUp->credentials);
    }

    /**
     * The classes of the step-up are those any credential reaches, each credential adding its own: a
     * hardware key reaches "phrh", the TOTP enrolled after it reaches "2" only, both are kept.
     */
    #[Test]
    public function theClassesAreGatheredFromEveryCredentialThatReachesOne(): void
    {
        // Given
        $passkey = Fixtures::passkey($this->alice);
        $totp = Totps::credential($this->alice, new FakePasswordHasher());

        // When
        $stepUp = StepUp::towards($this->password, [AuthenticationContextClass::phishingResistantHardware(), AuthenticationContextClass::twoFactors()], [$passkey, $totp]);

        // Then
        static::assertNotNull($stepUp);
        static::assertSame(['phrh', '2'], self::names($stepUp->classes));
        static::assertSame([$passkey, $totp], $stepUp->credentials);
    }

    /**
     * The classes kept are those some credential reaches, in the client's order: a synced passkey reaches
     * "phr" and not "phrh", which the client put first.
     */
    #[Test]
    public function theClassesAreThoseACredentialReachesInTheClientsOrder(): void
    {
        // Given
        $synced = Fixtures::passkey($this->alice, backupEligible: true, backedUp: true);

        // When
        $stepUp = StepUp::towards($this->password, [AuthenticationContextClass::phishingResistantHardware(), AuthenticationContextClass::twoFactors(), AuthenticationContextClass::phishingResistant()], [$synced]);

        // Then
        static::assertNotNull($stepUp);
        static::assertSame(['2', 'phr'], self::names($stepUp->classes));
    }

    /**
     * Each credential is judged on its own, as one login uses one of them: a TOTP after the password of
     * the session reaches "2", the passkey too, the password does not; the kinds are named once each, in
     * the order of enrolment.
     */
    #[Test]
    public function theCredentialsAreThoseThatWouldDoAndTheKindsAreNamedOnce(): void
    {
        // Given
        $totp = Totps::credential($this->alice, new FakePasswordHasher());
        $first = Fixtures::passkey($this->alice, 'YubiKey 5', 'first');
        $second = Fixtures::passkey($this->alice, 'Titan', 'second');

        // When
        $stepUp = StepUp::towards($this->password, [AuthenticationContextClass::twoFactors()], [Fixtures::password($this->alice), $totp, $first, $second]);

        // Then
        static::assertNotNull($stepUp);
        static::assertSame([$totp, $first, $second], $stepUp->credentials);
        static::assertSame(['totp', 'passkey'], $stepUp->kinds());
    }

    /**
     * The question a page may still ask of a step-up: whether one more login proving these methods, all
     * of them together, would satisfy a class the client accepts.
     */
    #[Test]
    public function itSaysWhetherALoginProvingGivenMethodsWouldMeetTheClient(): void
    {
        // Given
        $stepUp = StepUp::towards($this->password, [AuthenticationContextClass::phishingResistantHardware()], [Fixtures::passkey($this->alice)]);
        static::assertNotNull($stepUp);

        // When / Then
        static::assertTrue($stepUp->wouldBeMetBy([new AuthenticationMethod('hwk'), new AuthenticationMethod('user')]));
        static::assertFalse($stepUp->wouldBeMetBy([new AuthenticationMethod('swk'), new AuthenticationMethod('user')]));
    }

    #[Test]
    public function itReachesAtLeastOneClass(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A step-up reaches at least one class.');

        // When
        new StepUp($this->password, [], [Fixtures::passkey($this->alice)]);
    }

    #[Test]
    public function itIsMadeWithAtLeastOneCredential(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A step-up is made with at least one credential of the user.');

        // When
        new StepUp($this->password, [AuthenticationContextClass::phishingResistant()], []);
    }

    /**
     * @param list<AuthenticationContextClass> $classes
     *
     * @return list<string>
     */
    private static function names(array $classes): array
    {
        return array_map(static fn (AuthenticationContextClass $class): string => $class->value, $classes);
    }
}
