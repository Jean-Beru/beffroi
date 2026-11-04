<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Interaction;

use function array_map;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Totps;
use Beffroi\Oidc\Domain\Interaction\StepUp;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0010, Architecture §4.3
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

    #[Test]
    public function thereIsNoStepUpWhenNoCredentialOfTheUserReachesAClass(): void
    {
        // When / Then
        static::assertNull(StepUp::towards($this->password, [AuthenticationContextClass::phishingResistant()], [Fixtures::password($this->alice)]));
    }

    #[Test]
    public function thereIsNoStepUpWhenTheProofsSatisfyARequestedClassAlready(): void
    {
        // Given
        $proofs = AuthenticationProofs::ofAll([AuthenticationMethod::password(), new AuthenticationMethod('otp')], Fixtures::now());

        // When / Then
        static::assertNull(StepUp::towards($proofs, [AuthenticationContextClass::twoFactors()], [Fixtures::passkey($this->alice)]));
    }

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

    #[Test]
    public function theClassesAreGatheredFromEveryCredentialThatReachesOne(): void
    {
        // Given
        $passkey = Fixtures::passkey($this->alice);
        $totp = Totps::credential($this->alice, new FakePasswordHasher());

        // When
        $stepUp = StepUp::towards(
            $this->password,
            [AuthenticationContextClass::phishingResistantHardware(), AuthenticationContextClass::twoFactors()],
            [$passkey, $totp],
        );

        // Then
        static::assertNotNull($stepUp);
        static::assertSame(['phrh', '2'], self::names($stepUp->classes));
        static::assertSame([$passkey, $totp], $stepUp->credentials);
    }

    #[Test]
    public function theClassesAreThoseACredentialReachesInTheClientsOrder(): void
    {
        // Given
        $synced = Fixtures::passkey($this->alice, backupEligible: true, backedUp: true);

        // When
        $stepUp = StepUp::towards(
            $this->password,
            [
                AuthenticationContextClass::phishingResistantHardware(),
                AuthenticationContextClass::twoFactors(),
                AuthenticationContextClass::phishingResistant(),
            ],
            [$synced],
        );

        // Then
        static::assertNotNull($stepUp);
        static::assertSame(['2', 'phr'], self::names($stepUp->classes));
    }

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
