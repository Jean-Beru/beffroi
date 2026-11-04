<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Key;

use App\Doctrine\PersonalData\TenantDataKeyStores;
use App\Doctrine\PersonalData\TenantScopedEncrypter;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\CountingKms;
use Doctrine\DBAL\Connection;
use function in_array;
use function is_resource;
use function is_string;
use LogicException;
use SensitiveParameter;
use function sprintf;
use function stream_get_contents;
use function strlen;
use function substr;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\KeyManagement\Ciphertext;
use Symfony\Component\KeyManagement\DataKey;
use Symfony\Component\KeyManagement\DataKeyGeneratorInterface;
use Symfony\Component\KeyManagement\DecrypterInterface;
use Symfony\Component\KeyManagement\EncrypterInterface;
use Symfony\Component\KeyManagement\Exception\RuntimeException;

/**
 * Decision 0018
 */
final class DataKeyOutage implements DataKeyGeneratorInterface, DecrypterInterface, EncrypterInterface
{
    private const string CLIENT = 'key_management.test';

    /**
     * @var list<string>
     */
    public array $families = [];

    private (DataKeyGeneratorInterface&DecrypterInterface&EncrypterInterface)|null $kms = null;

    private ?Connection $connection = null;

    public function takeOver(ContainerInterface $container): void
    {
        $kms = $container->get(CountingKms::class);
        $connection = $container->get('doctrine.dbal.default_connection');
        if (! $kms instanceof CountingKms || ! $connection instanceof Connection) {
            throw new LogicException('The kernel has no KMS client to take over, or no connection to read the data keys with.');
        }
        $this->kms = $kms;
        $this->connection = $connection;
        $container->set(self::CLIENT, $this);
    }

    public function generateDataKey(string $keyId, int $length = 32, string $aad = ''): DataKey
    {
        return $this->kms()->generateDataKey($keyId, $length, $aad);
    }

    public function wrapDataKey(string $keyId, #[SensitiveParameter] string $dataKey, string $aad = ''): Ciphertext
    {
        return $this->kms()->wrapDataKey($keyId, $dataKey, $aad);
    }

    public function unwrapDataKey(Ciphertext $wrapped, string $aad = ''): DataKey
    {
        if ($this->refuses($wrapped)) {
            throw new RuntimeException(KmsOutage::WORDS_OF_THE_KMS);
        }

        return $this->kms()->unwrapDataKey($wrapped, $aad);
    }

    public function encrypt(string $keyId, #[SensitiveParameter] string $plaintext, string $aad = ''): Ciphertext
    {
        return $this->kms()->encrypt($keyId, $plaintext, $aad);
    }

    public function decrypt(Ciphertext $ciphertext, string $aad = ''): string
    {
        return $this->kms()->decrypt($ciphertext, $aad);
    }

    private function refuses(Ciphertext $wrapped): bool
    {
        if ($this->families === []) {
            return false;
        }
        $rows = $this->connection()->fetchAllAssociative(sprintf('SELECT scope, key_material FROM %s', TenantDataKeyStores::TABLE));
        foreach ($rows as $row) {
            $scope = $row['scope'];
            $material = is_resource($row['key_material']) ? stream_get_contents($row['key_material']) : $row['key_material'];
            if (is_string($scope) && $material === $wrapped->blob && in_array(self::familyOf($scope), $this->families, true)) {
                return true;
            }
        }

        return false;
    }

    private static function familyOf(string $scope): string
    {
        return substr($scope, strlen(TenantScopedEncrypter::slugOf($scope)) + strlen(TenantScopedEncrypter::SEPARATOR));
    }

    private function kms(): DataKeyGeneratorInterface&DecrypterInterface&EncrypterInterface
    {
        return $this->kms ?? throw new LogicException('The KMS of no kernel was taken over.');
    }

    private function connection(): Connection
    {
        return $this->connection ?? throw new LogicException('The connection of no kernel was taken over.');
    }
}
