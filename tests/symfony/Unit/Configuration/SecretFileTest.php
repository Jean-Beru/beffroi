<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use App\Configuration\SecretFile;
use function bin2hex;
use function file_put_contents;
use function is_file;
use function mkdir;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function rmdir;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\EnvNotFoundException;
use Symfony\Component\DependencyInjection\Exception\RuntimeException;
use function sys_get_temp_dir;
use function unlink;

final class SecretFileTest extends TestCase
{
    private const string VARIABLE = 'BEFFROI_SECRET_OF_THIS_TEST';

    private const string FILE = self::VARIABLE . SecretFile::SUFFIX;

    private string $directory = '';

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/beffroi-secret-file-' . bin2hex(random_bytes(8));
        mkdir($this->directory, 0o700);
    }

    protected function tearDown(): void
    {
        if (is_file($this->directory . '/secret')) {
            unlink($this->directory . '/secret');
        }
        rmdir($this->directory);
    }

    #[Test]
    public function theSecretIsWhatTheFileItsVariableNamesHolds(): void
    {
        // Given
        $path = $this->secretFile('s3cret');

        // When
        $secret = self::resolved([self::FILE => $path]);

        // Then
        static::assertSame('s3cret', $secret);
    }

    #[Test]
    #[DataProvider('provideLineBreaksAtTheEnd')]
    public function theLineBreaksAtTheEndOfTheFileAreNoPartOfTheSecret(string $content, string $expected): void
    {
        // Given
        $path = $this->secretFile($content);

        // When
        $secret = self::resolved([self::FILE => $path]);

        // Then
        static::assertSame($expected, $secret);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideLineBreaksAtTheEnd(): iterable
    {
        yield 'a line feed' => ["s3cret\n", 's3cret'];
        yield 'a carriage return and a line feed' => ["s3cret\r\n", 's3cret'];
        yield 'two line feeds' => ["s3cret\n\n", 's3cret'];
        yield 'a line feed inside, which stays' => ["s3\ncret\n", "s3\ncret"];
        yield 'spaces, which stay' => [" s3cret \n", ' s3cret '];
    }

    #[Test]
    public function withoutAFileTheVariableIsTheSecret(): void
    {
        // When
        $secret = self::resolved([self::VARIABLE => 's3cret']);

        // Then
        static::assertSame('s3cret', $secret);
    }

    #[Test]
    public function anEmptyFileVariableNamesNoFile(): void
    {
        // When
        $secret = self::resolved([self::FILE => '', self::VARIABLE => 's3cret']);

        // Then
        static::assertSame('s3cret', $secret);
    }

    #[Test]
    public function aSecretNamedByItsVariableAndByAFileIsRefused(): void
    {
        // Given
        $path = $this->secretFile('from the file');

        // Then
        $this->expectException(RuntimeException::class);

        // When
        self::resolved([self::FILE => $path, self::VARIABLE => 'from the variable']);
    }

    #[Test]
    public function theRefusalNamesBothVariablesAndNeitherSecret(): void
    {
        // Given
        $path = $this->secretFile('from the file');
        $refusal = '';

        // When
        try {
            self::resolved([self::FILE => $path, self::VARIABLE => 'from the variable']);
        } catch (RuntimeException $exception) {
            $refusal = $exception->getMessage();
        }

        // Then
        static::assertStringContainsString('"' . self::VARIABLE . '"', $refusal);
        static::assertStringContainsString('"' . self::FILE . '"', $refusal);
        static::assertStringNotContainsString('from the variable', $refusal);
        static::assertStringNotContainsString('from the file', $refusal);
    }

    #[Test]
    public function aValueTheEnvFilesGaveGivesWayToTheFile(): void
    {
        // Given
        $path = $this->secretFile('from the file');

        // When
        $secret = self::resolved([
            self::FILE => $path,
            self::VARIABLE => 'from the .env file',
            'SYMFONY_DOTENV_VARS' => 'APP_ENV,' . self::VARIABLE,
        ]);

        // Then
        static::assertSame('from the file', $secret);
    }

    #[Test]
    public function aFileThatCannotBeReadIsRefusedByItsVariableAndItsPath(): void
    {
        // Given
        $path = $this->directory . '/secret';
        $refusal = '';

        // When
        try {
            self::resolved([self::FILE => $path]);
        } catch (RuntimeException $exception) {
            $refusal = $exception->getMessage();
        }

        // Then
        static::assertStringContainsString('"' . self::FILE . '"', $refusal);
        static::assertStringContainsString($path, $refusal);
    }

    #[Test]
    public function aSecretNamedNeitherWayIsNotFound(): void
    {
        // Then
        $this->expectException(EnvNotFoundException::class);

        // When
        self::resolved([]);
    }

    #[Test]
    public function aDefaultTakesOverASecretNamedNeitherWay(): void
    {
        // Given
        $container = new ContainerBuilder();
        $container->register(SecretFile::class, SecretFile::class)->addTag('container.env_var_processor');
        $container->setParameter('secret', '%env(default::' . SecretFile::PREFIX . ':' . self::VARIABLE . ')%');
        $container->compile(true);

        // When
        $secret = $container->getParameter('secret');

        // Then
        static::assertNull($secret);
    }

    #[Test]
    public function aPlaceholderReadsTheFileItsVariableNames(): void
    {
        // Given
        $path = $this->secretFile('s3cret');
        $container = new ContainerBuilder();
        $container->register(SecretFile::class, SecretFile::class)->addTag('container.env_var_processor');
        $container->setParameter('env(' . self::FILE . ')', $path);
        $container->setParameter('secret', '%env(' . SecretFile::PREFIX . ':' . self::VARIABLE . ')%');
        $container->compile(true);

        // When
        $secret = $container->getParameter('secret');

        // Then
        static::assertSame('s3cret', $secret);
    }

    private function secretFile(string $content): string
    {
        $path = $this->directory . '/secret';
        file_put_contents($path, $content);

        return $path;
    }

    /**
     * @param array<string, string> $environment
     */
    private static function resolved(array $environment): mixed
    {
        $getEnv = static fn (string $name): string => $environment[$name] ?? throw new EnvNotFoundException($name);

        return new SecretFile()->getEnv(SecretFile::PREFIX, self::VARIABLE, $getEnv);
    }
}
