<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Key;

use function array_map;
use App\Key\KeysOpenedAtStart;
use App\Tests\Symfony\Functional\Command\ConsoleTestCase;
use Beffroi\Core\Domain\Key\KeptEncryptionAlgorithmInterface;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Key\UnsealedKey;
use Beffroi\Core\Port\KeptDecryptionKeyProviderInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Saml\Domain\Key\SamlEncryptionAlgorithmInterface;
use Closure;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Decision 0044
 */
final class KeysOpenedByAThreadTest extends ConsoleTestCase
{
    private const string SERVICE_PROVIDER = 'test_service_provider';

    private const string PROVIDER = 'https://idp-a.example/metadata';

    private KmsOutage $kms;

    protected function setUp(): void
    {
        $this->kms = new KmsOutage();
        parent::setUp();
    }

    protected static function kernelOptions(): array
    {
        return [
            'environment' => self::SERVICE_PROVIDER,
        ];
    }

    protected function configureContainer(): Closure
    {
        return function (ContainerInterface $container): void {
            $this->kms->takeOver($container);
        };
    }

    #[Test]
    public function aThreadOpensTheKeyAnUpstreamProviderEncryptsToBeforeTheKmsIsCut(): void
    {
        // Given
        $key = self::upstreamKey();
        $this->browser->getKernel()->shutdown();
        $this->browser->request('GET', '/jwks');
        self::service(KeysOpenedAtStart::BY_A_THREAD, KeysOpenedAtStart::class)->open();
        $this->kms->down = true;
        static::assertInstanceOf(KeptEncryptionAlgorithmInterface::class, $key->algorithm);

        // When
        $opened = self::service('test.beffroi.key_provider', KeptDecryptionKeyProviderInterface::class)
            ->keptDecryptionKeys(
                self::tenant(),
                $key->algorithm,
                [$key->kid],
            );

        // Then
        static::assertSame([$key->kid], array_map(static fn (UnsealedKey $opened): string => $opened->key->kid, $opened));
    }

    private static function upstreamKey(): TenantKey
    {
        $algorithm = SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::PROVIDER;
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => $algorithm,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        foreach (self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class)->findInService(self::tenant()) as $key) {
            if ($key->algorithm->name() === $algorithm) {
                return $key;
            }
        }

        return static::fail('The command drew no key.');
    }
}
