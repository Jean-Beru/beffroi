<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * OIDC Core §3.1.2.1 and §4: the "login_hint" of an authorization request, read back into the user it
 * names so that the field where a person types their name carries that name. The hint this provider
 * reads is above all the one it writes itself, a login begun at a client naming its user by the "sub"
 * that client holds, which for a client of its own sector is a string no row carries.
 */
final class LoginHintTest extends BrowserTestCase
{
    private const string LAUNCHED = 'launched-app';

    private const string LAUNCHED_REDIRECT_URI = 'https://launched.test/callback';

    private const string PAIRWISE = 'launched-pairwise-app';

    private const string PAIRWISE_REDIRECT_URI = 'https://launched-pairwise.test/callback';

    /**
     * OIDC Core §8 "public": a client that registers no kind holds the identifier the core keeps, and the
     * page reads it back into the name its user signs in with.
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
     * OIDC Core §4 end to end, which is what the reading is for: the provider begins a login at a client
     * of its own sector, the client carries the hint it was given into an authorization request once the
     * session here has ended, and the page that asks for the login again offers the name rather than the
     * "sub" the client holds (§8.1).
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
     * OIDC Core §8.1, the property pairwise exists for: a "sub" of one sector carried to a client of
     * another names nobody there, so the page offers nothing rather than telling the second client that
     * the string the first one holds is somebody here.
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
     * §3.1.2.1 makes the parameter a hint: one that names nobody leaves the field as a request carrying
     * none leaves it, and nobody is asked to delete a string they never typed.
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

    /**
     * What the client sent is read and never echoed: a page that carried the value back would show a
     * "sub" of one client to whoever is at the browser, and would do it for a value that named nobody.
     */
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

    /**
     * The value of the field a person types their name in, on the login page an authorization request
     * carrying that hint is sent to.
     */
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
