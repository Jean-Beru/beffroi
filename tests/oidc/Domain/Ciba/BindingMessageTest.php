<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Ciba;

use Beffroi\Oidc\Domain\Ciba\BindingMessage;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * CIBA Core §7.1, §13
 */
final class BindingMessageTest extends TestCase
{
    /**
     * CIBA Core §7.1
     */
    #[Test]
    #[DataProvider('provideAcceptedMessages')]
    public function itKeepsAPlainMessageAsItWasSent(string $message): void
    {
        // When / Then
        static::assertSame($message, new BindingMessage($message)->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAcceptedMessages(): iterable
    {
        yield 'a reference' => ['W4SCT'];
        yield 'words and digits' => ['Payment of 42 euros'];
        yield 'punctuation' => ['Order 1234: transfer to A. Martin (final)'];
        yield 'an accented sentence' => ['Paiement de 42,50 EUR chez Cafe du Coin'];
        yield 'a currency sign' => ['Paiement de 42,50 €'];
        yield 'as long as it may be' => [str_repeat('a', 64)];
    }

    /**
     * CIBA Core §13
     */
    #[Test]
    #[DataProvider('provideRefusedMessages')]
    public function itRefusesWhatCannotBeShownAsItIs(string $message, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        new BindingMessage($message);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRefusedMessages(): iterable
    {
        yield 'empty' => ['', 'A binding message is plain text'];
        yield 'longer than the page shows' => [str_repeat('a', 65), 'A binding message is at most 64 characters'];
        yield 'a new line' => ["Pay 42\nNow", 'A binding message is plain text'];
        yield 'a control character' => ["Pay 42\x07", 'A binding message is plain text'];
        yield 'markup' => ['<b>Pay 42</b>', 'A binding message is plain text'];
        yield 'an ampersand' => ['Pay 42 &amp; go', 'A binding message is plain text'];
        yield 'a quote' => ['Pay "42"', 'A binding message is plain text'];
        yield 'a direction override' => ["Pay 42\u{202E}", 'A binding message is plain text'];
        yield 'a zero width joiner' => ["Pay\u{200D}42", 'A binding message is plain text'];
    }

    #[Test]
    public function itIsItsOwnText(): void
    {
        // When / Then
        static::assertSame('Pay 42', (string) new BindingMessage('Pay 42'));
    }
}
