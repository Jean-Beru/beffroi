<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * OIDC Core §3.1.2.1, §4
 */
final class LoginHintTest extends BrowserTestCase
{
    private const string LAUNCHED = 'launched-app';

    private const string LAUNCHED_REDIRECT_URI = 'https://launched.test/callback';

    private const string PAIRWISE = 'launched-pairwise-app';

    private const string PAIRWISE_REDIRECT_URI = 'https://launched-pairwise.test/callback';

    /**
     * OIDC Core §8 "public"
     */
    #[Test]
    public function aHintThatIsASubjectOfTheClientOffersTheNameOfItsUser(): void
    {
        // Given
        $alice = self::user('alice');

        // When
        $offered = $this->nameOffered(self::LAUNCHED, self::LAUNCHED_REDIRECT_URI, $alice->subject->value);

        // Then
        static::assertSame('alice', $offered);
    }

    /**
     * OIDC Core §4, §8.1
     */
    #[Test]
    public function aPairwiseHintThisProviderWroteIsReadBackToTheNameOfItsUser(): void
    {
        // Given
        $alice = self::user('alice');
        $session = $this->signIn($alice);
        $this->browser->request('GET', '/initiate-login?client_id=' . self::PAIRWISE);
        $hint = self::redirectedQuery($this->browser->getResponse())['login_hint'];
        $this->endSession($session);

        // When
        $offered = $this->nameOffered(self::PAIRWISE, self::PAIRWISE_REDIRECT_URI, $hint);

        // Then
        static::assertNotSame($alice->subject->value, $hint);
        static::assertSame('alice', $offered);
    }

    /**
     * OIDC Core §8.1
     */
    #[Test]
    public function aHintOfAnotherSectorOffersNothing(): void
    {
        // Given
        $alice = self::user('alice');
        $session = $this->signIn($alice);
        $this->browser->request('GET', '/initiate-login?client_id=' . self::PAIRWISE);
        $hint = self::redirectedQuery($this->browser->getResponse())['login_hint'];
        $this->endSession($session);

        // When
        $offered = $this->nameOffered(self::LAUNCHED, self::LAUNCHED_REDIRECT_URI, $hint);

        // Then
        static::assertSame('', $offered);
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    #[DataProvider('provideHintsNamingNobody')]
    public function aHintThatNamesNobodyOffersNothing(?string $hint): void
    {
        // Given
        self::user('alice');

        // When
        $offered = $this->nameOffered(self::LAUNCHED, self::LAUNCHED_REDIRECT_URI, $hint);

        // Then
        static::assertSame('', $offered);
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function provideHintsNamingNobody(): iterable
    {
        yield 'a request that carries no hint at all' => [null];
        yield 'a subject nobody has' => ['bob-subject'];
        yield 'the name the user signs in with, which this tenant does not read a hint as' => ['alice'];
    }

    #[Test]
    public function theValueTheClientSentIsNowhereOnThePage(): void
    {
        // Given
        self::user('alice');
        $hint = 'a-subject-of-nobody-at-all';

        // When
        $this->loginPage(self::LAUNCHED, self::LAUNCHED_REDIRECT_URI, $hint);

        // Then
        static::assertStringNotContainsString($hint, self::string($this->browser->getResponse()->getContent()));
    }

    private function nameOffered(string $clientId, string $redirectUri, ?string $hint): string
    {
        $field = $this->loginPage($clientId, $redirectUri, $hint)->filter('input#username')->attr('value');

        return $field ?? static::fail('The login page offers no field to type a name in.');
    }

    private function loginPage(string $clientId, string $redirectUri, ?string $hint): Crawler
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters($clientId, [
            'redirect_uri' => $redirectUri,
            'login_hint' => $hint,
        ]));
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        $crawler = $this->browser->request('GET', '/login', [
            'interaction' => self::redirectedInteraction($response),
        ]);
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return $crawler;
    }
}
