<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Domain\Credential\PasswordLength;
use Beffroi\Core\Domain\Session\PhishingResistant;
use Beffroi\Core\Domain\Session\SingleFactor;
use Beffroi\Core\Domain\Session\TwoFactors;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * How long a password has to be, which NIST SP 800-63B §3.1.1.2 makes two numbers: fifteen characters for
 * a password used as a single-factor authentication mechanism, eight for one only used as part of a
 * multi-factor process. Which of the two a password is held to is read off the floor of the logins of its
 * tenant (decision 0025) and off nothing kept beside it.
 */
final class PasswordLengthTest extends TestCase
{
    /**
     * NIST SP 800-63B §3.1.1.2: "Verifiers and CSPs SHALL require passwords that are used as a
     * single-factor authentication mechanism to be a minimum of 15 characters in length." A tenant that
     * names no floor stands on this one, so fifteen is what this provider asks unless a tenant says
     * otherwise.
     */
    #[Test]
    public function aPasswordThatIsTheWholeOfALoginReachesFifteenCharacters(): void
    {
        // When / Then
        static::assertSame(15, PasswordLength::under(new SingleFactor())->minimum);
    }

    /**
     * NIST SP 800-63B §3.1.1.2: a password "only used as part of multi-factor authentication processes"
     * may be shorter, down to eight characters. Under two factors a password satisfies nothing by itself
     * and is half of what satisfies the floor, which is what makes it such a password.
     */
    #[Test]
    public function aPasswordASecondFactorIsReadBesideReachesEightCharacters(): void
    {
        // When / Then
        static::assertSame(8, PasswordLength::under(new TwoFactors())->minimum);
    }

    /**
     * A floor that reads nothing a password proves holds no password at all (issue #327): the shorter of
     * the two numbers is what it is answered, and no password ever reaches it, the enrolment being refused
     * before anything is posed (EnrolmentRefusal).
     */
    #[Test]
    public function aFloorThatReadsNoPasswordIsAnsweredTheShorterLength(): void
    {
        // When / Then
        static::assertSame(8, PasswordLength::under(new PhishingResistant())->minimum);
    }

    /**
     * Counted in characters and not in bytes, which §3.1.1.2 asks for: "each Unicode code point SHALL be
     * counted as a single character when evaluating password length". Fifteen accented characters are
     * thirty bytes and are fifteen characters.
     */
    #[Test]
    public function fifteenMultibyteCharactersReachFifteen(): void
    {
        // Given
        $length = PasswordLength::under(new SingleFactor());

        // When / Then
        static::assertTrue($length->reachedBy(str_repeat('é', 15)));
    }

    #[Test]
    public function oneCharacterShortDoesNotReachIt(): void
    {
        // Given
        $length = PasswordLength::under(new SingleFactor());

        // When / Then
        static::assertFalse($length->reachedBy(str_repeat('é', 14)));
    }
}
