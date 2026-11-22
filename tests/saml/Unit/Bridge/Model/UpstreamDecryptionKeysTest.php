<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Application\Metadata\EncryptionCertificates;
use Beffroi\Saml\Bridge\Model\UpstreamDecryptionKeys;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Tests\Fixture\RecordingKeptDecryptionKeys;
use Beffroi\Saml\Tests\Fixture\SamlEncryption;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use Beffroi\Saml\Tests\Fixture\WiredAlgorithmsOf;
use Beffroi\Core\Tests\Fixture\FakeSignatureAlgorithm;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use DateTimeImmutable;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Writing\ResponseWriterFixtures;
use Beffroi\Saml2\Model\Writing\Encryption;
use Beffroi\Saml2\Model\Writing\ResponseWriter;
use Beffroi\Saml2\Model\Writing\SignedParts;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Enc\DecryptionKeyInterface;
use Beffroi\Xml\Enc\EncryptedData;
use Beffroi\Xml\Enc\Exception\DecryptionFailed;
use Beffroi\Xml\Enc\PeerKey;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-64, S-66, section 6.13, S-65
 */
final class UpstreamDecryptionKeysTest extends TestCase
{
    private const string PROVIDER = 'https://idp-a.example/metadata';

    private const string OTHER_PROVIDER = 'https://idp-b.example/metadata';

    private const string FIXTURE_PROVIDER = 'https://idp.example.com/saml';

    private const string FIXTURE_OTHER_PROVIDER = 'https://idp-b.example.com/saml';

    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private OpenedKeys $held;

    private RecordingKeptDecryptionKeys $opened;

    private WiredAlgorithmsOf $wired;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryTenantKeyRepository();
        $this->held = Keys::opened();
        $this->opened = new RecordingKeptDecryptionKeys(new SealedKeyProvider($this->keys, $this->held));
        $this->wired = new WiredAlgorithmsOf([
            new SamlEncryption(self::PROVIDER),
            new SamlEncryption(self::OTHER_PROVIDER),
            new SamlEncryption(self::FIXTURE_PROVIDER),
            new SamlEncryption(self::FIXTURE_OTHER_PROVIDER),
        ]);
    }

    /**
     * S-66
     */
    #[Test]
    public function anAssertionEncryptedForThePublishedCertificateIsRead(): void
    {
        // Given
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::PROVIDER));
        $response = ResponseWriterFixtures::response();

        // When
        $accepted = ResponseWriterFixtures::validator()->validate(
            $this->encryptedFor($response, self::PROVIDER),
            ResponseWriterFixtures::identityProvider()->withDecryptionKey($this->keyOf(self::PROVIDER)),
            ResponseWriterFixtures::expected(),
        );

        // Then
        static::assertEquals($response->assertion, $accepted->assertion);
    }

    /**
     * S-66, enc.md E-3
     */
    #[Test]
    public function theCiphertextOfAProviderPresentedUnderAnotherIsRefused(): void
    {
        // Given
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::PROVIDER));
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::OTHER_PROVIDER, 1));
        $response = $this->encryptedFor(ResponseWriterFixtures::response(), self::PROVIDER);

        // Then
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessageIs('The data could not be decrypted (E-3).');

        // When
        ResponseWriterFixtures::validator()->validate(
            $response,
            ResponseWriterFixtures::identityProvider()->withDecryptionKey($this->keyOf(self::OTHER_PROVIDER)),
            ResponseWriterFixtures::expected(),
        );
    }

    /**
     * S-66
     */
    #[Test]
    public function theKeyACiphertextWasMadeForIsNeverAskedUnderAnotherProvider(): void
    {
        // Given
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::PROVIDER));
        $other = SamlKeys::encryptionKey($this->tenant, self::OTHER_PROVIDER, 1);
        $this->keys->save($other);
        $response = $this->encryptedFor(ResponseWriterFixtures::response(), self::PROVIDER);

        // When
        try {
            ResponseWriterFixtures::validator()->validate(
                $response,
                ResponseWriterFixtures::identityProvider()->withDecryptionKey($this->keyOf(self::OTHER_PROVIDER)),
                ResponseWriterFixtures::expected(),
            );
        } catch (DecryptionFailed) {
        }

        // Then
        static::assertSame([$other->kid], $this->opened->asked);
    }

    /**
     * S-66, decision 0013, enc.md E-15
     */
    #[Test]
    public function theKeyOfAnotherProviderUnwrapsNothingOfACiphertextMadeForTheFirst(): void
    {
        // Given
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::PROVIDER));
        $other = SamlKeys::encryptionKey($this->tenant, self::OTHER_PROVIDER, 1);
        $this->keys->save($other);
        $data = $this->encryptedDataOf($this->encryptedFor(ResponseWriterFixtures::response(), self::PROVIDER));

        // When
        $sessionKey = $this->keyOf(self::OTHER_PROVIDER)->unwrap($data->key->cipherValue, $data->key->transport->hash);

        // Then
        static::assertSame([null, [$other->kid]], [$sessionKey, $this->opened->asked]);
    }

    /**
     * S-66, decision 0013, enc.md E-15, E-16
     */
    #[Test]
    public function anotherProviderReplayingTheCbcCiphertextOfAProviderGetsTheOneFailure(): void
    {
        // Given
        $this->keys->save(SamlKeys::encryptionKeyOfPem($this->tenant, self::FIXTURE_PROVIDER, MetadataFixtures::bytes('keys/sp-signing-key.pem')));
        $other = SamlKeys::encryptionKeyOfPem($this->tenant, self::FIXTURE_OTHER_PROVIDER, MetadataFixtures::bytes('keys/sp-b-encryption-key.pem'));
        $this->keys->save($other);
        $response = UnverifiedResponse::of(SamlLoader::create()->load(MetadataFixtures::bytes('encrypted/response-aes128-cbc-ciphertext-of-another-provider-signed-by-b-refused.xml')));
        $data = $this->encryptedDataOf($response);
        $signer = new IdentityProvider(
            self::FIXTURE_OTHER_PROVIDER,
            [MetadataFixtures::certificate('idp-b')],
            [],
            [new Endpoint(Binding::HttpRedirect, 'https://idp-b.example.com/saml/sso')],
        );

        // When
        try {
            new ResponseValidator(SamlLoader::create(), new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00Z')), new InMemoryReplayGuard())->validate(
                $response,
                $signer->withDecryptionKey($this->keyOf(self::FIXTURE_OTHER_PROVIDER)),
                ExpectedResponse::toRequest('_request', 'https://sp.example.com/saml/acs', 'https://sp.example.com/saml'),
            );
            static::fail('The ciphertext of a provider was read under the signature of another.');
        } catch (DecryptionFailed $failure) {
            // Then
            static::assertSame([DecryptionFailed::MESSAGE, [$other->kid]], [$failure->getMessage(), $this->opened->asked]);
            static::assertNull($this->keyOf(self::FIXTURE_OTHER_PROVIDER)->unwrap($data->key->cipherValue, $data->key->transport->hash));
        }
    }

    /**
     * S-65, S-66
     */
    #[Test]
    public function anAssertionEncryptedForThePreviousCertificateIsReadUntilItsKeyRetires(): void
    {
        // Given
        $previous = $this->activeKey(SamlKeys::encryptionKey($this->tenant, self::PROVIDER));
        $response = ResponseWriterFixtures::response();
        $encrypted = $this->encryptedFor($response, self::PROVIDER);
        $this->rotate($previous);

        // When
        $accepted = ResponseWriterFixtures::validator()->validate(
            $encrypted,
            ResponseWriterFixtures::identityProvider()->withDecryptionKey($this->keyOf(self::PROVIDER)),
            ResponseWriterFixtures::expected(),
        );

        // Then
        static::assertEquals($response->assertion, $accepted->assertion);
    }

    /**
     * S-66
     */
    #[Test]
    public function anAssertionEncryptedForARetiredKeyIsRefused(): void
    {
        // Given
        $previous = $this->activeKey(SamlKeys::encryptionKey($this->tenant, self::PROVIDER));
        $encrypted = $this->encryptedFor(ResponseWriterFixtures::response(), self::PROVIDER);
        $this->rotate($previous);
        $previous->retire(Fixtures::now());

        // Then
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessageIs('The data could not be decrypted (E-3).');

        // When
        ResponseWriterFixtures::validator()->validate(
            $encrypted,
            ResponseWriterFixtures::identityProvider()->withDecryptionKey($this->keyOf(self::PROVIDER)),
            ResponseWriterFixtures::expected(),
        );
    }

    /**
     * S-65, S-66
     */
    #[Test]
    public function anAssertionEncryptedForTheStagedCertificateIsRead(): void
    {
        // Given
        $this->activeKey(SamlKeys::encryptionKey($this->tenant, self::PROVIDER));
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::PROVIDER, 2, Fixtures::now()->modify('+1 day')));
        $response = ResponseWriterFixtures::response();

        // When
        $accepted = ResponseWriterFixtures::validator()->validate(
            $this->encryptedFor($response, self::PROVIDER),
            ResponseWriterFixtures::identityProvider()->withDecryptionKey($this->keyOf(self::PROVIDER)),
            ResponseWriterFixtures::expected(),
        );

        // Then
        static::assertEquals($response->assertion, $accepted->assertion);
    }

    /**
     * Section 6.13 step 1
     */
    #[Test]
    public function aProviderWithoutAKeyIsGivenNone(): void
    {
        // Given
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::OTHER_PROVIDER));

        // When
        $key = new UpstreamDecryptionKeys($this->keys, $this->wired, $this->opened)->of($this->tenant, self::PROVIDER);

        // Then
        static::assertNull($key);
    }

    /**
     * Section 6.13 step 1
     */
    #[Test]
    public function aProviderNothingWiresIsGivenNone(): void
    {
        // Given
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::PROVIDER));
        $keys = new UpstreamDecryptionKeys($this->keys, new WiredAlgorithmsOf([new SamlEncryption(self::OTHER_PROVIDER)]), $this->opened);

        // When
        $key = $keys->of($this->tenant, self::PROVIDER);

        // Then
        static::assertSame([null, []], [$key, $this->opened->asked]);
    }

    /**
     * S-64
     */
    #[Test]
    public function anAlgorithmThatIsNoKeyOfAProviderGivesNone(): void
    {
        // Given
        $keys = new UpstreamDecryptionKeys(
            $this->keys,
            new WiredAlgorithmsOf([new FakeSignatureAlgorithm('SAML-ENCRYPTION:' . self::PROVIDER)]),
            $this->opened,
        );

        // When / Then
        static::assertNull($keys->of($this->tenant, self::PROVIDER));
    }

    /**
     * Section 6.13 step 2
     */
    #[Test]
    public function aKeyRetiredSinceTheLastResponseLeavesTheProcess(): void
    {
        // Given
        $previous = SamlKeys::encryptionKey($this->tenant, self::PROVIDER);
        $previous->activate(Fixtures::now());
        $this->keys->save($previous);
        $this->keyOf(self::PROVIDER);
        $held = $this->held->open($this->tenant, $previous);
        $this->rotate($previous);
        $previous->retire(Fixtures::now());

        // When
        $this->keyOf(self::PROVIDER);

        // Then
        static::assertNotSame($held, $this->held->open($this->tenant, $previous));
    }

    /**
     * Section 6.13 step 2
     */
    #[Test]
    public function theKeysOfAProviderThatHaveAllRetiredLeaveTheProcess(): void
    {
        // Given
        $previous = SamlKeys::encryptionKey($this->tenant, self::PROVIDER);
        $previous->activate(Fixtures::now());
        $this->keys->save($previous);
        $this->keyOf(self::PROVIDER);
        $held = $this->held->open($this->tenant, $previous);
        $previous->startRetiring(Fixtures::now(), Fixtures::now());
        $previous->retire(Fixtures::now());

        // When
        new UpstreamDecryptionKeys($this->keys, $this->wired, $this->opened)->of($this->tenant, self::PROVIDER);

        // Then
        static::assertNotSame($held, $this->held->open($this->tenant, $previous));
    }

    /**
     * Section 6.13 step 2
     */
    #[Test]
    public function aKmsThatDoesNotAnswerRefusesBeforeAnythingIsUnwrapped(): void
    {
        // Given
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::PROVIDER));
        $sealer = self::createStub(KeySealerInterface::class);
        $sealer->method('unseal')->willThrowException(new KmsUnavailableException('The KMS does not answer.'));
        $keys = new UpstreamDecryptionKeys($this->keys, $this->wired, new SealedKeyProvider($this->keys, new OpenedKeys($sealer)));

        // Then
        $this->expectException(KmsUnavailableException::class);
        $this->expectExceptionMessageIs('The KMS does not answer.');

        // When
        $keys->of($this->tenant, self::PROVIDER);
    }

    /**
     * Section 6.13
     */
    private function keyOf(string $identityProvider): DecryptionKeyInterface
    {
        $key = new UpstreamDecryptionKeys($this->keys, $this->wired, $this->opened)->of($this->tenant, $identityProvider);
        static::assertNotNull($key);

        return $key;
    }

    /**
     * S-19, S-65
     */
    private function encryptedFor(Response $response, string $identityProvider): UnverifiedResponse
    {
        $certificates = new EncryptionCertificates($this->keys, Keys::sealer(), new SelfSignedCertificateIssuer())->of($this->tenant, $identityProvider);
        static::assertNotSame([], $certificates);

        return UnverifiedResponse::of(SamlLoader::create()->load(new Serializer()->serialize(new ResponseWriter()->write(
            $response,
            new Signing(MetadataFixtures::signingKey('idp')),
            SignedParts::AssertionAndResponse,
            new Encryption(PeerKey::fromCertificateBase64($certificates[0]->base64)),
        ))));
    }

    private function encryptedDataOf(UnverifiedResponse $response): EncryptedData
    {
        return EncryptedData::of(Children::one(
            Children::one($response->document->root(), new Name('urn:oasis:names:tc:SAML:2.0:assertion', 'EncryptedAssertion')),
            new Name('http://www.w3.org/2001/04/xmlenc#', 'EncryptedData'),
        ));
    }

    private function activeKey(TenantKey $key): TenantKey
    {
        $key->activate(Fixtures::now());
        $this->keys->save($key);

        return $key;
    }

    private function rotate(TenantKey $previous): void
    {
        $this->activeKey(SamlKeys::encryptionKey($this->tenant, self::PROVIDER, 2, Fixtures::now()->modify('+1 day')));
        $previous->startRetiring(Fixtures::now(), Fixtures::now()->modify('+1 hour'));
    }
}
