<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Twig;

use App\Twig\ClientNameExtension;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Translation\Loader\ArrayLoader;
use Symfony\Component\Translation\Translator;
use Twig\Environment;
use Twig\Extension\AttributeExtension;
use Twig\Loader\ArrayLoader as TemplateLoader;
use Twig\RuntimeLoader\FactoryRuntimeLoader;
use Twig\TwigFilter;

/**
 * OIDC Registration §2: client_name, the name a client gave itself.
 */
final class ClientNameTest extends TestCase
{
    #[Test]
    public function theNameAClientGaveItselfIsSetApartInTheSentence(): void
    {
        // When
        $sentence = self::extension()->translate('consent.request', 'Link audit');

        // Then
        static::assertSame('<b data-client-name>Link audit</b> asks for access to:', $sentence);
    }

    /**
     * @param array<string, string> $parameters
     */
    #[Test]
    #[DataProvider('provideWhatAClientWrites')]
    public function whatAClientWritesIsNeverMarkup(string $message, string $client, array $parameters, string $expected): void
    {
        // When
        $sentence = self::extension()->translate($message, $client, $parameters);

        // Then
        static::assertSame($expected, $sentence);
    }

    /**
     * @return iterable<string, array{string, string, array<string, string>, string}>
     */
    public static function provideWhatAClientWrites(): iterable
    {
        yield 'markup in its name' => [
            'consent.request',
            '<img src=x onerror=alert(1)>',
            [],
            '<b data-client-name>&lt;img src=x onerror=alert(1)&gt;</b> asks for access to:',
        ];
        yield 'markup in what it asks the person to read' => [
            'approvals.binding_message',
            'Acme',
            ['message' => '<i>Pay</i> & go'],
            '<b data-client-name>Acme</b> says: &lt;i&gt;Pay&lt;/i&gt; &amp; go',
        ];
        yield 'the character that stands for the name in what it asks the person to read' => [
            'approvals.binding_message',
            'Acme',
            ['message' => "Pay \u{E000}now"],
            '<b data-client-name>Acme</b> says: Pay now',
        ];
    }

    #[Test]
    public function aSentenceAPageChoosesBetweenTwoIsNotEscapedASecondTime(): void
    {
        // Given
        $twig = new Environment(new TemplateLoader([
            'page' => "{{ alone ? 'login.prompt_alone'|trans : 'consent.request'|trans_with_client(name) }}",
        ]));
        $twig->addExtension(new AttributeExtension(ClientNameExtension::class));
        $twig->addRuntimeLoader(new FactoryRuntimeLoader([ClientNameExtension::class => self::extension(...)]));
        $twig->addFilter(new TwigFilter('trans', static fn (string $message): string => $message));

        // When
        $page = $twig->render('page', ['alone' => false, 'name' => 'Link <audit>']);

        // Then
        static::assertSame('<b data-client-name>Link &lt;audit&gt;</b> asks for access to:', $page);
    }

    private static function extension(): ClientNameExtension
    {
        $translator = new Translator('en');
        $translator->addLoader('array', new ArrayLoader());
        $translator->addResource(
            'array',
            [
                'consent.request' => '{client} asks for access to:',
                'approvals.binding_message' => '{client} says: {message}',
            ],
            'en',
            'beffroi+intl-icu',
        );

        return new ClientNameExtension($translator);
    }
}
