<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Support;

use Beffroi\Saml2\Bindings\PostForm;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class BrowserFormTest extends TestCase
{
    /**
     * URL Standard §5
     */
    #[Test]
    public function itEncodesTheBodyAsABrowserDoes(): void
    {
        // When
        $body = BrowserForm::body([
            ['SAMLResponse',   'ab+/=='],
            ['RelayState',     'a b&c'],
            ['SAMLResponse[]', 'x'],
        ]);

        // Then
        static::assertSame('SAMLResponse=ab%2B%2F%3D%3D&RelayState=a+b%26c&SAMLResponse%5B%5D=x', $body);
    }

    /**
     * Section 6.8
     */
    #[Test]
    public function itGivesTheFieldsAsPhpParsesThem(): void
    {
        // When
        $fields = BrowserForm::posted([
            ['SAMLResponse', "ab+/\r\n=="],
            ['RelayState',   'a b&c'],
            ['RelayState[]', 'x'],
        ]);

        // Then
        static::assertSame(['SAMLResponse' => "ab+/\r\n==", 'RelayState' => ['x']], $fields);
    }

    /**
     * Section 6.7
     */
    #[Test]
    public function itSubmitsTheFieldsOfAPostForm(): void
    {
        // Given
        $form = new PostForm('https://sp.example.com/saml/acs?a=b', [
            'SAMLResponse' => 'ab+/==',
            'RelayState' => '<a b>',
        ]);

        // When
        $fields = BrowserForm::submitted($form);

        // Then
        static::assertSame(['SAMLResponse' => 'ab+/==', 'RelayState' => '<a b>'], $fields);
    }
}
