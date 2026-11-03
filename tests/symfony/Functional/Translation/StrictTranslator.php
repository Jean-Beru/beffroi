<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Translation;

use LogicException;
use function sprintf;
use function str_starts_with;
use Symfony\Component\Translation\MessageCatalogueInterface;
use Symfony\Component\Translation\TranslatorBagInterface;
use Symfony\Contracts\Translation\LocaleAwareInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * The translator of the test kernel refuses what the translator of an application hides: a message no
 * catalogue of the requested language defines fails the request instead of showing its key, or its
 * English (architecture §5.7: every string a user reads is translated, in every locale the provider ships).
 * A parent locale is a catalogue of the same language ("fr" for "fr_CA") and is looked at; the fallback
 * to the default locale of the deployment is not: that is the one that hides a missing French sentence
 * behind the English one.
 */
final readonly class StrictTranslator implements TranslatorInterface, TranslatorBagInterface, LocaleAwareInterface
{
    public function __construct(
        private TranslatorInterface&TranslatorBagInterface&LocaleAwareInterface $inner,
    ) {
    }

    /**
     * @param array<array-key, mixed> $parameters
     */
    public function trans(string $id, array $parameters = [], ?string $domain = null, ?string $locale = null): string
    {
        if ($id !== '') {
            $this->assertDefined($id, $domain ?? 'messages', $locale);
        }

        return $this->inner->trans($id, $parameters, $domain, $locale);
    }

    public function getCatalogue(?string $locale = null): MessageCatalogueInterface
    {
        return $this->inner->getCatalogue($locale);
    }

    public function getCatalogues(): array
    {
        return $this->inner->getCatalogues();
    }

    public function getLocale(): string
    {
        return $this->inner->getLocale();
    }

    public function setLocale(string $locale): void
    {
        $this->inner->setLocale($locale);
    }

    private function assertDefined(string $id, string $domain, ?string $locale): void
    {
        $catalogue = $this->inner->getCatalogue($locale);
        $requested = $catalogue->getLocale();
        while (! $catalogue->defines($id, $domain)) {
            $fallback = $catalogue->getFallbackCatalogue();
            if ($fallback === null || ! str_starts_with($requested, $fallback->getLocale() . '_')) {
                throw new LogicException(sprintf('No translation of "%s" in the "%s" domain for the "%s" locale.', $id, $domain, $requested));
            }
            $catalogue = $fallback;
        }
    }
}
