<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Domain\Credential\Attestation\ModelProof;
use Beffroi\Core\Tests\Fixture\AttestationAuthority;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;

/**
 * WebAuthn Level 3 §5.4.7, Decision 0046
 */
final class DirectPasskeyAttestationTest extends PasskeyAttestationTestCase
{
    protected static function policy(): array
    {
        return [
            'BEFFROI_TEST_PASSKEY_ATTESTATION' => 'direct',
        ];
    }

    #[Test]
    public function theCreationOptionsAskForADirectAttestation(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $options = json_decode($this->creationOptions(), true, 8, JSON_THROW_ON_ERROR);

        // Then
        static::assertIsArray($options);
        static::assertSame('direct', $options['attestation'] ?? null);
    }

    /**
     * §7.1 step 22
     */
    #[Test]
    public function aKeyWhoseModelTheMetadataKnowIsShownVerified(): void
    {
        // Given
        $maker = AttestationAuthority::create('Maker of the tests');
        $this->theMetadataKnowTheModel([AuthenticatorStatus::FIDO_CERTIFIED], [$maker->rootInMetadata()]);
        $alice = self::user('alice');

        // When
        $page = $this->tryToEnrol($alice, $this->attested($maker->attest()));

        // Then
        static::assertSame(ModelProof::Verified, self::passkeysOf($alice)[0]->modelProof);
        static::assertSame('verified', $page->filter('[data-model-proof]')->attr('data-model-proof'));
    }

    /**
     * §5.4.7: an attestation is a preference, which the client is free to answer with none.
     */
    #[Test]
    public function aKeyThatSendsNoAttestationIsEnrolledWithItsModelDeclared(): void
    {
        // Given
        $alice = self::user('alice');

        // When
        $page = $this->tryToEnrol($alice, self::device());

        // Then
        static::assertSame(ModelProof::Declared, self::passkeysOf($alice)[0]->modelProof);
        static::assertSame('declared', $page->filter('[data-model-proof]')->attr('data-model-proof'));
        static::assertCount(1, $page->filter('p[data-authenticators-declared]'));
    }

    /**
     * FIDO Metadata Service v3.1.1 §3.1.4.2
     */
    #[Test]
    public function aKeyOfAModelUnderASecurityAlertIsRefusedAndThePageSaysWhy(): void
    {
        // Given
        $maker = AttestationAuthority::create('Maker of the tests');
        $this->theMetadataKnowTheModel([AuthenticatorStatus::USER_VERIFICATION_BYPASS], [$maker->rootInMetadata()]);
        $alice = self::user('alice');

        // When
        $page = $this->tryToEnrol($alice, $this->attested($maker->attest()));

        // Then
        static::assertSame([], self::passkeysOf($alice));
        static::assertSame('model_under_security_alert', $page->filter('p[data-error]')->attr('data-error'));
        static::assertStringContainsString('under a security alert', $page->filter('p[data-error]')->text());
    }
}
