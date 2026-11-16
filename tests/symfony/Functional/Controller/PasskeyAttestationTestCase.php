<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Doctrine\TenantSynchronizer;
use App\Webauthn\FileMetadataBlobStore;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Tests\Fixture\AttestationCertificate;
use Beffroi\Core\Tests\Fixture\MetadataBlobs;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use function is_string;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use function random_bytes;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0046
 */
abstract class PasskeyAttestationTestCase extends PasskeyTestCase
{
    private const array VARIABLES = [
        'BEFFROI_TEST_PASSKEY_ATTESTATION',
        'BEFFROI_TEST_PASSKEY_ATTESTATION_ROOTS',
        'BEFFROI_TEST_PASSKEY_ATTESTATION_OWN_ROOTS',
        'BEFFROI_TEST_PASSKEY_COMPROMISED_MODELS',
    ];

    protected string $aaguid;

    /**
     * @return array<string, mixed> each variable of the policy to its value, a list or an object being written as JSON
     */
    abstract protected static function policy(): array;

    protected function setUp(): void
    {
        foreach (static::policy() as $variable => $value) {
            $_SERVER[$variable] = is_string($value) ? $value : json_encode($value, JSON_THROW_ON_ERROR);
        }
        parent::setUp();
        self::service('test.beffroi.tenant_synchronizer', TenantSynchronizer::class)->synchronize();
        self::reload();
        $this->aaguid = random_bytes(16);
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        foreach (self::VARIABLES as $variable) {
            unset($_SERVER[$variable], $_ENV[$variable]);
        }
    }

    protected static function kernelOptions(): array
    {
        return [
            'environment' => 'test_passkey_attestation',
        ];
    }

    /**
     * @param list<string> $statuses
     * @param list<string> $roots attestationRootCertificates
     */
    protected function theMetadataKnowTheModel(array $statuses, array $roots): void
    {
        new FileMetadataBlobStore(self::metadataStorage())->write('mds', MetadataBlobs::payload([MetadataBlobs::entry(
            Uuid::fromBinary($this->aaguid)->toRfc4122(),
            $statuses,
            attestationRootCertificates: $roots,
        )]));
    }

    protected function attested(AttestationCertificate $certificate): SoftwareAuthenticator
    {
        return new SoftwareAuthenticator(self::ORIGIN, attestation: 'packed', aaguid: $this->aaguid, attestedBy: $certificate);
    }

    /**
     * The passkeys page after the attestation was posted, whatever became of it.
     */
    protected function tryToEnrol(User $user, SoftwareAuthenticator $device): Crawler
    {
        $this->signIn($user);
        $token = $this->passkeysPage()->filter('form[data-passkey="enrol"] input[name="_token"]')->attr('value');
        static::assertIsString($token);
        $this->browser->request('POST', '/account/passkeys', [
            '_token' => $token,
            'name' => 'The key of the organisation',
            '_passkey' => $device->create($this->creationOptions()),
        ]);

        return $this->afterTheForm();
    }

    /**
     * @return list<PasskeyCredential>
     */
    protected static function passkeysOf(User $user): array
    {
        self::reload();

        return self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($user, PasskeyCredential::class);
    }
}
