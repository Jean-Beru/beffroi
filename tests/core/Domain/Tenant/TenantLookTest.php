<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Tenant;

use Beffroi\Core\Domain\Tenant\LogoUri;
use Beffroi\Core\Domain\Tenant\TenantLook;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Issue #449: what a tenant gives the pages of its provider besides its name.
 */
final class TenantLookTest extends TestCase
{
    #[Test]
    public function aTenantThatDeclaredNothingDeclaresNothing(): void
    {
        // When / Then
        static::assertFalse(TenantLook::none()->isDeclared());
    }

    #[Test]
    public function aLogoAloneIsDeclared(): void
    {
        // When / Then
        static::assertTrue(new TenantLook(new LogoUri('https://acme.example/logo.svg'))->isDeclared());
    }

    #[Test]
    public function coloursAloneAreDeclared(): void
    {
        // When / Then
        static::assertTrue(new TenantLook(primaryColor: '#1b4b8f', primaryContentColor: '#ffffff')->isDeclared());
    }

    /**
     * The value reaches a browser inside a style attribute, so what it may hold is hexadecimal digits and
     * nothing else: a named colour, a function, a variable and anything carrying a semicolon are refused
     * rather than escaped (decision 0006).
     */
    #[Test]
    #[DataProvider('provideRefusedColors')]
    public function itRefusesAColourThatIsNotHexadecimal(string $color): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('must be three or six hexadecimal digits behind a hash');

        // When
        new TenantLook(primaryColor: $color, primaryContentColor: '#ffffff');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedColors(): iterable
    {
        yield 'a name' => ['rebeccapurple'];
        yield 'no hash' => ['1b4b8f'];
        yield 'four digits' => ['#1b4b'];
        yield 'an alpha form' => ['#1b4b8fcc'];
        yield 'a function' => ['rgb(27, 75, 143)'];
        yield 'a variable' => ['var(--brand)'];
        yield 'a declaration of its own' => ['#1b4b8f; display: none'];
        yield 'empty' => [''];
    }

    #[Test]
    #[DataProvider('provideAcceptedColors')]
    public function itAcceptsTheTwoHexadecimalForms(string $color): void
    {
        // When / Then
        static::assertSame($color, new TenantLook(primaryColor: $color, primaryContentColor: '#fff')->primaryColor);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAcceptedColors(): iterable
    {
        yield 'six digits' => ['#1b4b8f'];
        yield 'three digits' => ['#1b4'];
        yield 'uppercase' => ['#1B4B8F'];
    }

    #[Test]
    public function itRefusesAColourWithoutTheColourOfWhatIsWrittenOnIt(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('together, or neither of them');

        // When
        new TenantLook(primaryColor: '#1b4b8f');
    }

    #[Test]
    public function itRefusesTheColourOfWhatIsWrittenWithoutTheColourItIsWrittenOn(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('together, or neither of them');

        // When
        new TenantLook(primaryContentColor: '#ffffff');
    }

    #[Test]
    public function twoLooksAreTheSameWhenEveryValueIs(): void
    {
        // Given
        $look = new TenantLook(new LogoUri('https://acme.example/logo.svg'), '#1b4b8f', '#ffffff');

        // When / Then
        static::assertTrue($look->equals(new TenantLook(new LogoUri('https://acme.example/logo.svg'), '#1b4b8f', '#ffffff')));
    }

    #[Test]
    #[DataProvider('provideDifferentLooks')]
    public function twoLooksDifferWhenOneValueDoes(TenantLook $other): void
    {
        // Given
        $look = new TenantLook(new LogoUri('https://acme.example/logo.svg'), '#1b4b8f', '#ffffff');

        // When / Then
        static::assertFalse($look->equals($other));
    }

    /**
     * @return iterable<string, array{TenantLook}>
     */
    public static function provideDifferentLooks(): iterable
    {
        yield 'another logo' => [new TenantLook(new LogoUri('https://acme.example/mark.svg'), '#1b4b8f', '#ffffff')];
        yield 'no logo' => [new TenantLook(null, '#1b4b8f', '#ffffff')];
        yield 'another colour' => [new TenantLook(new LogoUri('https://acme.example/logo.svg'), '#0f766e', '#ffffff')];
        yield 'another colour on it' => [new TenantLook(new LogoUri('https://acme.example/logo.svg'), '#1b4b8f', '#000000')];
        yield 'nothing' => [TenantLook::none()];
    }

    #[Test]
    public function aLookWithNoLogoIsTheSameAsAnotherWithNone(): void
    {
        // When / Then
        static::assertTrue(new TenantLook(null, '#1b4b8f', '#ffffff')->equals(new TenantLook(null, '#1b4b8f', '#ffffff')));
    }
}
