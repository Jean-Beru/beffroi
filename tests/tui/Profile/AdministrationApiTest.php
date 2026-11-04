<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Profile;

use Beffroi\Tui\Profile\AdministrationApi;
use Beffroi\Tui\Profile\ProfileException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8707 §2: the administration API is named by an absolute URI without a fragment, served over HTTPS.
 */
final class AdministrationApiTest extends TestCase
{
    #[Test]
    public function anHttpsUriNamesTheAdministrationApi(): void
    {
        // When
        $identifier = AdministrationApi::identifier('https://admin.op.example/v1');

        // Then
        static::assertSame('https://admin.op.example/v1', $identifier);
    }

    #[Test]
    #[DataProvider('provideValuesThatNameNoApi')]
    public function aValueThatIsNoHttpsUriWithoutAQueryOrAFragmentIsRefused(string $value): void
    {
        // Then
        $this->expectException(ProfileException::class);
        $this->expectExceptionMessageIsOrContains('names no administration API');

        // When
        AdministrationApi::identifier($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValuesThatNameNoApi(): iterable
    {
        yield 'a path alone' => ['/administration'];
        yield 'plain HTTP' => ['http://admin.op.example'];
        yield 'a fragment' => ['https://admin.op.example/#api'];
        yield 'a query' => ['https://admin.op.example/?tenant=acme'];
        yield 'no host' => ['https:///administration'];
        yield 'nothing' => [''];
    }
}
