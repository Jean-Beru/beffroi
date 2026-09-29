<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Key;

use function base64_decode;
use function file_get_contents;
use function file_put_contents;
use Heidi\Bundle\Key\FilePairwiseSalt;
use Heidi\Core\Bridge\Random\PlatformRandomness;
use Heidi\Core\Exception\RuntimeException;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Tests\Fixture\FakeSecretSealer;
use function mkdir;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sys_get_temp_dir;
use Symfony\Component\Filesystem\Filesystem;
use function uniqid;

/**
 * OIDC Core §8.1: the salt a tenant computes its pairwise identifiers with, kept where its sealed keys are
 * kept and sealed like them (architecture §3.3).
 */
final class FilePairwiseSaltTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/heidi-pairwise-salt-' . uniqid();
    }

    protected function tearDown(): void
    {
        new Filesystem()->remove($this->directory);
    }

    /**
     * It is drawn on first use and never again: the second read is the first salt, so every identifier the
     * tenant ever handed out stays the identifier it handed out.
     */
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

    /**
     * It is a secret of its tenant: what a deployment keeps for one tenant computes nothing for another, so
     * two tenants give the same user and the same sector two identifiers.
     */
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

    /**
     * It is never written in clear: what is on disk is the envelope the KMS of the tenant made of it.
     */
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

    /**
     * An envelope of another tenant does not open here, which is what a KMS of a deployment guarantees: the
     * salt is refused rather than read as bytes that compute other identifiers.
     */
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
