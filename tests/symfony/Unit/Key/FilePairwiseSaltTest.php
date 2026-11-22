<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Key;

use function base64_decode;
use function file_get_contents;
use function file_put_contents;
use App\Key\FilePairwiseSalt;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Tests\Fixture\FakeSecretSealer;
use function mkdir;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sys_get_temp_dir;
use Symfony\Component\Filesystem\Filesystem;
use function uniqid;

/**
 * OIDC Core §8.1, Architecture §3.3
 */
final class FilePairwiseSaltTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/beffroi-pairwise-salt-' . uniqid();
    }

    protected function tearDown(): void
    {
        new Filesystem()->remove($this->directory);
    }

    #[Test]
    public function itIsDrawnOnceAndReadBackAfterwards(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $salts = $this->salts();

        // When
        $drawn = $salts->saltOf($tenant);
        $again = $this->salts()->saltOf($tenant);

        // Then
        static::assertSame($drawn, $again);
    }

    #[Test]
    public function twoTenantsOfOneDeploymentDrawTwoSalts(): void
    {
        // Given
        $salts = $this->salts();

        // When
        $here = $salts->saltOf(Fixtures::tenant('here', 'https://here.example'));
        $there = $salts->saltOf(Fixtures::tenant('there', 'https://there.example'));

        // Then
        static::assertNotSame($here, $there);
    }

    #[Test]
    public function whatIsOnDiskIsSealedForItsTenant(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $drawn = $this->salts()->saltOf($tenant);

        // When
        $kept = file_get_contents($this->directory . '/' . $tenant->slug . '/' . FilePairwiseSalt::FILE);

        // Then
        static::assertIsString($kept);
        static::assertSame('sealed:acme:' . $drawn, base64_decode($kept, true));
    }

    #[Test]
    public function anEnvelopeOfAnotherTenantIsRefused(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $this->salts()->saltOf(Fixtures::tenant('other', 'https://other.example'));
        $stolen = file_get_contents($this->directory . '/other/' . FilePairwiseSalt::FILE);
        static::assertIsString($stolen);
        mkdir($this->directory . '/' . $tenant->slug, 0o700, true);
        file_put_contents($this->directory . '/' . $tenant->slug . '/' . FilePairwiseSalt::FILE, $stolen);

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs('The envelope was not sealed for the tenant "acme".');

        // When
        $this->salts()->saltOf($tenant);
    }

    private function salts(): FilePairwiseSalt
    {
        return new FilePairwiseSalt($this->directory, new FakeSecretSealer(), new PlatformRandomness());
    }
}
