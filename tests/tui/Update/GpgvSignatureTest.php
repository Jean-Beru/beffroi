<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Update;

use Beffroi\Tui\Tests\Fixture\FakeGpgv;
use Beffroi\Tui\Update\GpgvSignature;
use Beffroi\Tui\Update\SelfUpdateException;
use function explode;
use function file_get_contents;
use function file_put_contents;
use function getenv;
use function is_executable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_replace;
use function str_starts_with;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

/**
 * The signature of `SHA256SUMS` verified by gpgv: what the verifier makes of each answer of gpgv, then the gpgv of
 * the machine on signatures made by keys of the fixture, where GnuPG is installed.
 */
final class GpgvSignatureTest extends TestCase
{
    private const string FIXTURE = __DIR__ . '/../Fixture/Release';

    /**
     * The key of the fixture, which signed `SHA256SUMS.asc`; `SHA256SUMS.by-another-key.asc` is signed by
     * AA55341CBFE12FA5A797CC36F5A650443CF52D5E, which the keyring does not hold.
     */
    private const string FIXTURE_KEY = 'F381E5A569AE09CF195BF879E689B4DEB95A98BA';

    private const string SUBKEY = '0123456789ABCDEF0123456789ABCDEF01234567';

    private ?FakeGpgv $gpgv = null;

    private ?string $altered = null;

    protected function tearDown(): void
    {
        $this->gpgv?->remove();
        if ($this->altered !== null) {
            @unlink($this->altered);
        }
    }

    #[Test]
    public function aSignatureGpgvReportsValidForThePinnedPrimaryKeyVouches(): void
    {
        // Given
        $this->gpgv = FakeGpgv::answering(['NEWSIG', 'GOODSIG E689B4DEB95A98BA Fixture', FakeGpgv::validSignature(self::SUBKEY, self::FIXTURE_KEY)], 0);

        // When
        self::verifier($this->gpgv->directory)->verify(self::FIXTURE . '/SHA256SUMS', self::FIXTURE . '/SHA256SUMS.asc');

        // Then
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function gpgvReadsAHomeAndAKeyringOfItsOwnAndNoKeyOfTheMachine(): void
    {
        // Given
        $this->gpgv = FakeGpgv::answering([FakeGpgv::validSignature(self::FIXTURE_KEY, self::FIXTURE_KEY)], 0);

        // When
        self::verifier($this->gpgv->directory)->verify(self::FIXTURE . '/SHA256SUMS', self::FIXTURE . '/SHA256SUMS.asc');

        // Then
        $arguments = $this->gpgv->arguments();
        static::assertSame(
            [
                '--homedir',
                '--status-fd',
                '1',
                '--keyring',
                $arguments[1] . '/keyring.gpg',
                self::FIXTURE . '/SHA256SUMS.asc',
                self::FIXTURE . '/SHA256SUMS',
                true,
            ],
            [
                $arguments[0],
                $arguments[2],
                $arguments[3],
                $arguments[4],
                $arguments[5],
                $arguments[6],
                $arguments[7],
                str_starts_with($arguments[1], sys_get_temp_dir() . '/beffroi-tui-'),
            ],
        );
    }

    /**
     * @param list<string> $status
     */
    #[Test]
    #[DataProvider('provideAnswersThatDoNotVouch')]
    public function anAnswerOfGpgvThatDoesNotVouchForThePinnedKeyIsRefused(array $status, int $exit): void
    {
        // Given
        $this->gpgv = FakeGpgv::answering($status, $exit);

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs(sprintf('gpgv finds no good signature by the key %s in SHA256SUMS.asc: nothing is replaced.', self::FIXTURE_KEY));

        // When
        self::verifier($this->gpgv->directory)->verify(self::FIXTURE . '/SHA256SUMS', self::FIXTURE . '/SHA256SUMS.asc');
    }

    /**
     * @return iterable<string, array{list<string>, int}>
     */
    public static function provideAnswersThatDoNotVouch(): iterable
    {
        yield 'a bad signature' => [['NEWSIG', 'BADSIG E689B4DEB95A98BA Fixture'], 1];
        yield 'no public key' => [['NEWSIG', 'ERRSIG E689B4DEB95A98BA 1 10 00 1795383807 9 -', 'NO_PUBKEY E689B4DEB95A98BA'], 2];
        yield 'a good end without a valid signature' => [['NEWSIG'], 0];
        yield 'a valid signature of another primary key' => [[FakeGpgv::validSignature(self::FIXTURE_KEY, self::SUBKEY)], 0];
        yield 'a valid signature for the pinned key, and a bad end' => [[FakeGpgv::validSignature(self::FIXTURE_KEY, self::FIXTURE_KEY)], 1];
    }

    #[Test]
    public function withoutGpgvNothingIsVerified(): void
    {
        // Given
        $verifier = new GpgvSignature(self::FIXTURE . '/keyring.gpg', self::FIXTURE_KEY, sys_get_temp_dir() . '/no-such-directory:');

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs('The signature of a release is verified by gpgv, which none of the directories of PATH holds: install GnuPG, then run the update again.');

        // When
        $verifier->verify(self::FIXTURE . '/SHA256SUMS', self::FIXTURE . '/SHA256SUMS.asc');
    }

    #[Test]
    public function theGpgvOfTheMachineVouchesForASignatureOfThePinnedKey(): void
    {
        // Given
        $verifier = self::verifier(self::gpgvOfTheMachine());

        // When
        $verifier->verify(self::FIXTURE . '/SHA256SUMS', self::FIXTURE . '/SHA256SUMS.asc');

        // Then
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function theGpgvOfTheMachineRefusesASignatureOfSumsThatChanged(): void
    {
        // Given
        $verifier = self::verifier(self::gpgvOfTheMachine());
        $this->altered = sprintf('%s/beffroi-tui-SHA256SUMS-%s', sys_get_temp_dir(), uniqid());
        file_put_contents($this->altered, str_replace('f426e530', 'f426e531', (string) file_get_contents(self::FIXTURE . '/SHA256SUMS')));

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs(sprintf('gpgv finds no good signature by the key %s in SHA256SUMS.asc: nothing is replaced.', self::FIXTURE_KEY));

        // When
        $verifier->verify($this->altered, self::FIXTURE . '/SHA256SUMS.asc');
    }

    #[Test]
    public function theGpgvOfTheMachineRefusesASignatureOfAKeyTheKeyringDoesNotHold(): void
    {
        // Given
        $verifier = self::verifier(self::gpgvOfTheMachine());

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs(sprintf(
            'gpgv finds no good signature by the key %s in SHA256SUMS.by-another-key.asc: nothing is replaced.',
            self::FIXTURE_KEY,
        ));

        // When
        $verifier->verify(self::FIXTURE . '/SHA256SUMS', self::FIXTURE . '/SHA256SUMS.by-another-key.asc');
    }

    #[Test]
    public function theGpgvOfTheMachineVouchesForNothingWhenTheKeyringHoldsAnotherKeyThanThePinnedOne(): void
    {
        // Given
        $verifier = new GpgvSignature(self::FIXTURE . '/keyring.gpg', GpgvSignature::RELEASES, self::gpgvOfTheMachine());

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs(sprintf('gpgv finds no good signature by the key %s in SHA256SUMS.asc: nothing is replaced.', GpgvSignature::RELEASES));

        // When
        $verifier->verify(self::FIXTURE . '/SHA256SUMS', self::FIXTURE . '/SHA256SUMS.asc');
    }

    /**
     * The tag 4.2.7 of web-token/jwt-framework is signed by the key the releases are signed with.
     */
    #[Test]
    public function theGpgvOfTheMachineVouchesForASignatureOfTheReleaseKeyUnderTheKeyringTheProgramCarries(): void
    {
        // Given
        $verifier = GpgvSignature::ofTheReleases(['PATH' => self::gpgvOfTheMachine()]);

        // When
        $verifier->verify(self::FIXTURE . '/jwt-framework-4.2.7.tag', self::FIXTURE . '/jwt-framework-4.2.7.tag.asc');

        // Then
        $this->expectNotToPerformAssertions();
    }

    private static function verifier(string $path): GpgvSignature
    {
        return new GpgvSignature(self::FIXTURE . '/keyring.gpg', self::FIXTURE_KEY, $path);
    }

    /**
     * The directory of the PATH of this run that holds gpgv; the test is skipped where GnuPG is not installed, as in
     * the image of the CI, where the tests above stand for it.
     */
    private static function gpgvOfTheMachine(): string
    {
        foreach (explode(':', (string) getenv('PATH')) as $directory) {
            if ($directory !== '' && is_executable($directory . '/gpgv')) {
                return $directory;
            }
        }

        static::markTestSkipped('gpgv is on none of the directories of PATH: the gpgv of the machine is played only where GnuPG is installed.');
    }
}
