<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Core\Domain\Key\KeyStatus;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\SamlLoader;
use function array_find;
use function array_map;
use function base64_decode;
use function chunk_split;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function openssl_x509_read;
use PHPUnit\Framework\Attributes\Test;
use function strtr;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Response;

/**
 * beffroi/saml, spec/saml.md sections 6.1 and 9: the metadata of the SAML identity provider of the tenant, served on
 * the protocol plane, its key drawn and rotated by the key commands as every key of the tenant.
 */
final class IdentityProviderMetadataTest extends ConsoleTestCase
{
    private const string METADATA = '/saml/metadata';

    /**
     * Section 6.1, S-4: the metadata served is read back by saml2-model's MetadataReader, its entity ID the URL of the
     * metadata under the issuer, both services at their URL on both bindings, WantAuthnRequestsSigned true as the
     * tenant left it, the certificate of its one key.
     */
    #[Test]
    public function theMetadataOfTheTenantIsReadBackByTheModel(): void
    {
        // Given
        self::generate();

        // When
        $this->browser->request('GET', self::METADATA);

        // Then
        $descriptor = $this->servedDescriptor();
        $identityProvider = $descriptor->identityProvider;
        static::assertNotNull($identityProvider);
        static::assertSame(
            [
                'https://op.test/saml/metadata',
                true,
                1,
                [
                    [Binding::HttpRedirect, 'https://op.test/saml/sso'],
                    [Binding::HttpPost,     'https://op.test/saml/sso'],
                ],
                [
                    [Binding::HttpRedirect, 'https://op.test/saml/slo'],
                    [Binding::HttpPost,     'https://op.test/saml/slo'],
                ],
            ],
            [
                $descriptor->entityId,
                $identityProvider->wantAuthnRequestsSigned,
                \count($identityProvider->signingCertificates),
                array_map(static fn ($endpoint): array => [$endpoint->binding, $endpoint->location], $identityProvider->singleSignOnServices),
                array_map(static fn ($endpoint): array => [$endpoint->binding, $endpoint->location], $identityProvider->singleLogoutServices),
            ],
        );
    }

    /**
     * Section 6.1 step 6: served as SAML metadata, cacheable for the max-age of the keys of the tenant, two minutes in
     * this kernel, which its staging window derives from.
     */
    #[Test]
    public function itIsServedAsSamlMetadataForTheMaxAgeOfTheKeys(): void
    {
        // Given
        self::generate();

        // When
        $this->browser->request('GET', self::METADATA);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            ['application/samlmetadata+xml', true, '120'],
            [
                $response->headers->get('Content-Type'),
                $response->headers->hasCacheControlDirective('public'),
                $response->headers->getCacheControlDirective('max-age'),
            ],
        );
    }

    /**
     * S-1, S-3: the certificate served is around the public half of the SAML key the tenant holds, and that key is not
     * in the JWK Set.
     */
    #[Test]
    public function theCertificateIsAroundTheSamlKeyWhichTheJwkSetDoesNotCarry(): void
    {
        // Given
        $key = self::generate();
        $this->browser->request('GET', self::METADATA);
        $certificates = $this->servedDescriptor()->identityProvider->signingCertificates ?? [];

        // When
        $this->browser->request('GET', '/jwks');

        // Then
        static::assertSame(
            [[self::base64url($key->publicJwk['n'])], []],
            [array_map(self::modulusOf(...), $certificates), self::json($this->browser->getResponse())['keys'] ?? null],
        );
    }

    /**
     * S-2: a rotation of the SAML key stages the next one, whose certificate is served beside the current one's before
     * the staged key signs anything.
     */
    #[Test]
    public function aRotationPublishesTheNextCertificateBeforeItSigns(): void
    {
        // Given
        $current = self::generate();
        // a key created later, so that the creation order of the two is the order they were drawn in
        self::aSecondLater();
        $rotation = self::console('beffroi:keys:rotate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $rotation->getStatusCode(), $rotation->getDisplay());
        $next = array_find(
            self::keys()->findInService(self::tenant()),
            static fn (TenantKey $key): bool => $key->isStaged(),
        ) ?? static::fail('The rotation staged no key.');

        // When
        $this->browser->request('GET', self::METADATA);

        // Then
        static::assertSame(
            [KeyStatus::Staged, [self::base64url($current->publicJwk['n']), self::base64url($next->publicJwk['n'])]],
            [$next->status, array_map(self::modulusOf(...), $this->servedDescriptor()->identityProvider->signingCertificates ?? [])],
        );
    }

    /**
     * Section 6.1 step 1: a tenant that holds no SAML key has no metadata to serve.
     */
    #[Test]
    public function aTenantWithoutASamlKeyServesNoMetadata(): void
    {
        // When
        $this->browser->request('GET', self::METADATA);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * The first SAML key of the tenant, drawn by the command an operator runs and active at once.
     */
    private static function generate(): TenantKey
    {
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());

        return self::keys()->findInService(self::tenant())[0] ?? static::fail('The command drew no key.');
    }

    private static function keys(): TenantKeyRepositoryInterface
    {
        return self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class);
    }

    private function servedDescriptor(): EntityDescriptor
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());

        return new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(SamlLoader::create()->load(self::string($response->getContent())));
    }

    private static function modulusOf(string $certificate): string
    {
        $x509 = openssl_x509_read("-----BEGIN CERTIFICATE-----\n" . chunk_split($certificate, 64, "\n") . "-----END CERTIFICATE-----\n");
        static::assertNotFalse($x509);
        $public = openssl_pkey_get_public($x509);
        static::assertNotFalse($public);
        $details = openssl_pkey_get_details($public);
        static::assertIsArray($details);
        static::assertIsArray($details['rsa'] ?? null);

        return self::string($details['rsa']['n'] ?? null);
    }

    private static function base64url(string $value): string
    {
        return self::string(base64_decode(strtr($value, '-_', '+/'), true));
    }
}
