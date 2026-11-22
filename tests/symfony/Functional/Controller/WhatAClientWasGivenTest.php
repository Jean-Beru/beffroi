<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function array_column;
use function base64_encode;
use App\Tests\Symfony\Functional\Command\ConsoleTestCase;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use const JSON_THROW_ON_ERROR;
use function json_decode;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

final class WhatAClientWasGivenTest extends ConsoleTestCase
{
    #[Test]
    public function theArchiveHoldsWhatEachApplicationWasGivenAtEachAct(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->tokensOfTheDemoClient();

        // When
        $disclosures = $this->disclosuresOfTheArchive();

        // Then
        static::assertSame([TokensIssued::NAME], array_column($disclosures, 'act'));
        static::assertSame(['oidc-demo'], array_column($disclosures, 'client_id'));
        static::assertSame([['openid', 'profile']], array_column($disclosures, 'scopes'));
        static::assertSame(['jwt'], array_column($disclosures, 'token_shape'));
    }

    #[Test]
    public function whatWasGivenOutlivesTheConsentItWasGivenUnder(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->tokensOfTheDemoClient();
        self::console(
            'beffroi:user:revoke-consent',
            [
                'username' => 'alice',
                'client-id' => 'oidc-demo',
            ],
            [],
            false,
        );

        // When
        $document = $this->archive();

        // Then
        static::assertSame([], self::chapter($document, 'consents'));
        static::assertSame([TokensIssued::NAME], array_column(self::chapter($document, 'disclosures'), 'act'));
    }

    /**
     * RFC 6749 §4.4
     */
    #[Test]
    public function whatAClientObtainedForItselfIsInNobodysRegister(): void
    {
        // Given
        self::signingKey();
        $alice = self::user('alice');
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'client_credentials',
                'scope' => 'invoices.read',
                'resource' => 'https://cal.example.com/',
            ],
            server: self::credentials('service-app', 'service-secret-of-at-least-32-characters-l'),
        );
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));
        $this->signIn($alice);

        // When / Then
        static::assertSame([], $this->disclosuresOfTheArchive());
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function disclosuresOfTheArchive(): array
    {
        return self::chapter($this->archive(), 'disclosures');
    }

    /**
     * @return array<string, mixed>
     */
    private function archive(): array
    {
        $page = $this->browser->request('GET', '/account/archive');
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));
        $this->browser->request('POST', '/account/archive', [
            '_token' => self::string($page->filter('form[data-archive-ask] input[name="_token"]')->attr('value')),
        ]);
        $this->afterTheForm();
        $this->browser->request('GET', '/account/archive/file');
        $document = json_decode(self::string($this->browser->getResponse()->getContent()), true, 512, JSON_THROW_ON_ERROR);
        static::assertIsArray($document);

        /** @var array<string, mixed> $document */
        return $document;
    }

    /**
     * @param array<string, mixed> $document
     *
     * @return list<array<string, mixed>>
     */
    private static function chapter(array $document, string $name): array
    {
        $chapter = $document[$name] ?? null;
        static::assertIsArray($chapter);

        /** @var list<array<string, mixed>> $chapter */
        return $chapter;
    }

    private function tokensOfTheDemoClient(): void
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => 'https://demo.test/login/check',
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: self::credentials('oidc-demo', 'demo-secret-of-at-least-32-characters-long'),
        );
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));
    }

    /**
     * @return array<string, string>
     */
    private static function credentials(string $clientId, string $secret): array
    {
        return [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($clientId . ':' . $secret),
        ];
    }
}
