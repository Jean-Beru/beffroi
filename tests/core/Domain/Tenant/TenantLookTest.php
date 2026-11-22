<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Tenant;

use Beffroi\Core\Domain\Tenant\LogoUri;
use Beffroi\Core\Domain\Tenant\TenantLook;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

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
     * Decision 0006
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
        yield 'a line feed behind a colour that would pass' => ["#1b4b8f\n"];
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

    /**
     * @param array<string, string> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itWritesTheDocumentAColumnHoldsItAs(TenantLook $look, array $document): void
    {
        // When / Then
        static::assertSame($document, $look->toDocument());
    }

    /**
     * @param array<string, string> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itComesBackOutOfItsDocument(TenantLook $look, array $document): void
    {
        // When / Then
        static::assertEquals($look, TenantLook::fromDocument($document));
    }

    /**
     * @return iterable<string, array{TenantLook, array<string, string>}>
     */
    public static function provideDocuments(): iterable
    {
        yield 'a look' => [
            new TenantLook(new LogoUri('https://acme.example/logo.svg'), '#1b4b8f', '#ffffff'),
            [
                'logo_uri' => 'https://acme.example/logo.svg',
                'primary_color' => '#1b4b8f',
                'primary_content_color' => '#ffffff',
            ],
        ];
        yield 'a logo and no colour' => [
            new TenantLook(new LogoUri('https://acme.example/logo.svg')),
            [
                'logo_uri' => 'https://acme.example/logo.svg',
            ],
        ];
        yield 'a tenant that declared none' => [TenantLook::none(), []];
    }

    /**
     * @param array<array-key, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsThatAreNotALook')]
    public function aDocumentThatIsNotALookIsRefused(array $document, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        TenantLook::fromDocument($document);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function provideDocumentsThatAreNotALook(): iterable
    {
        yield 'a numeric colour' => [
            [
                'primary_color' => 27,
                'primary_content_color' => '#ffffff',
            ],
            'The member "primary_color" must be a string or absent.',
        ];
        yield 'a colour the object refuses' => [
            [
                'primary_color' => 'rebeccapurple',
                'primary_content_color' => '#ffffff',
            ],
            'The primary colour "rebeccapurple" of a tenant must be three or six hexadecimal digits behind a hash, as "#1b4b8f".',
        ];
        yield 'one colour alone' => [
            [
                'primary_color' => '#1b4b8f',
            ],
            'A tenant declares the colour of its pages and the colour of what is written on it together, or neither of them.',
        ];
    }
}
