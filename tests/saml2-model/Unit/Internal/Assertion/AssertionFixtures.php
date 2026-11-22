<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion;

use Beffroi\Saml2\Model\Internal\Assertion\AssertionContext;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use DateTimeImmutable;
use Dom\Element;
use function file_get_contents;
use function mb_strlen;
use function sprintf;
use function str_contains;

trait AssertionFixtures
{
    private function document(string $fixture): Document
    {
        $bytes = file_get_contents(__DIR__ . '/../../../Fixture/' . $fixture);
        static::assertIsString($bytes);

        return SamlLoader::create()->load($bytes);
    }

    private function child(Document $document, string $local): Element
    {
        return Children::one($document->root(), new Name(Saml::ASSERTION, $local));
    }

    /**
     * @param ?string $inResponseTo null for an unsolicited response (M-10)
     */
    private function context(?string $inResponseTo = '_request'): AssertionContext
    {
        return new AssertionContext(
            new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00Z'))->now(),
            new TimeBounds(),
            'https://idp.example.com/saml',
            'https://sp.example.com/saml',
            'https://sp.example.com/saml/acs',
            $inResponseTo,
        );
    }

    /**
     * M-16: values shorter than three characters are not compared, any sentence holds them.
     */
    private static function assertCarriesNothingOf(string $message, Document $document): void
    {
        foreach (self::values($document->root()) as $value) {
            static::assertFalse(
                mb_strlen($value) >= 3 && str_contains($message, $value),
                sprintf('The message carries a value of the input: %s', $value),
            );
        }
    }

    /**
     * @return list<string>
     */
    private static function values(Element $element): array
    {
        $values = [];
        foreach ($element->attributes as $attribute) {
            $values[] = $attribute->value;
        }
        $children = Children::all($element);
        if ($children === []) {
            $values[] = Text::of($element);
        }
        foreach ($children as $child) {
            $values = [...$values, ...self::values($child)];
        }

        return $values;
    }
}
