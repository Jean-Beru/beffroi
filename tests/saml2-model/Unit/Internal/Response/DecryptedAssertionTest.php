<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Response;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Response\DecryptedAssertion;
use Beffroi\Saml2\Model\SamlLoader;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.7 step 4, M-4
 */
final class DecryptedAssertionTest extends TestCase
{
    use ResponseFixtures;

    /**
     * Section 6.7 step 4, M-4
     */
    #[Test]
    public function itHoldsAPlaintextWhoseRootIsAnAssertion(): void
    {
        // Given
        $plaintext = SamlLoader::create()->load('<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion" Version="2.0"/>');

        // When
        $decrypted = DecryptedAssertion::of($plaintext);

        // Then
        static::assertSame($plaintext, $decrypted->document);
    }

    /**
     * §9.2 row 41, M-4
     */
    #[Test]
    public function itRefusesAPlaintextThatIsNotAnAssertion(): void
    {
        // Given
        $plaintext = $this->document('behaviour/response-signed-assertion-accepted.xml');
        $message = 'The plaintext of the saml:EncryptedAssertion is not a saml:Assertion (M-4).';

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $plaintext);

        // When
        DecryptedAssertion::of($plaintext);
    }
}
