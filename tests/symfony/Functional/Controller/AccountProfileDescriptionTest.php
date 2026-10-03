<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #452, architecture §5.2: a person changes what the tenant lets them change of themselves. The
 * kernel of these tests opens two claims, so both ends of the rule are played: what is open is written,
 * and what is not is refused on the server and not merely left off the page.
 */
final class AccountProfileDescriptionTest extends BrowserTestCase
{
    #[Test]
    public function thePageOffersAFieldPerClaimTheTenantOpens(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->profilePage();

        // Then
        // in the order the claims are wired and not the order the tenant named them, which is what the
        // page says of itself (WiredClaims)
        static::assertSame(['nickname', 'locale', 'zoneinfo'], $page->filter('form[data-changeable]')->extract(['data-changeable']));
    }

    /**
     * Issue #476: the page renders the field the claim says it is, and a text box stops standing in for
     * every one of them.
     */
    #[Test]
    public function theFieldIsOfTheKindTheClaimSays(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->profilePage();

        // Then
        static::assertSame(['text'], $page->filter('form[data-changeable="nickname"] input[name="value"]')->extract(['data-field']));
        // a closed set is chosen from, and the languages served are the one closed set these claims have
        static::assertSame(['choice'], $page->filter('form[data-changeable="locale"] select[name="value"]')->extract(['data-field']));
        static::assertSame(['en', 'fr'], $page->filter('form[data-changeable="locale"] option[value!=""]')->extract(['value']));
        // six hundred names of a database are a picker and not a choice: what a zone gets is an example
        static::assertSame(['Europe/Paris'], $page->filter('form[data-changeable="zoneinfo"] input[name="value"]')->extract(['placeholder']));
    }

    #[Test]
    public function aPersonSaysSomethingOfThemselves(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $this->describe('nickname', 'Ada');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('Ada', self::reread($alice)->profile->nickname);
    }

    #[Test]
    public function anEmptyFieldTakesBackWhatTheyHadSaid(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $this->describe('nickname', 'Ada');

        // When
        $this->describe('nickname', '');

        // Then
        static::assertNull(self::reread($alice)->profile->nickname);
    }

    /**
     * The page does not offer it, and the form can be sent anyway: what refuses is the server.
     */
    #[Test]
    public function aClaimTheTenantDoesNotOpenIsRefusedOnTheServer(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $this->describe('family_name', 'Lovelace');

        // Then
        static::assertSame(Response::HTTP_UNPROCESSABLE_ENTITY, $this->browser->getResponse()->getStatusCode());
        static::assertNull(self::reread($alice)->profile->familyName);
    }

    #[Test]
    public function aClaimThisProviderDoesNotHoldIsNothingAtAll(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->describe('favourite_colour', 'blue');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aFormSentWithoutTheTokenOfItsPageIsRefused(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $this->browser->request('POST', '/account/profile', [
            'claim' => 'nickname',
            'value' => 'Ada',
        ]);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertNull(self::reread($alice)->profile->nickname);
    }

    #[Test]
    public function aBrowserWithNoSessionIsRefused(): void
    {
        // When
        $this->browser->request('POST', '/account/profile', [
            'claim' => 'nickname',
            'value' => 'Ada',
        ]);

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    private function describe(string $claim, string $value): void
    {
        $token = self::string($this->profilePage()->filter('form[data-changeable="nickname"] input[name="_token"]')->attr('value'));
        $this->browser->request('POST', '/account/profile', [
            '_token' => $token,
            'claim' => $claim,
            'value' => $value,
        ]);
    }

    private function profilePage(): Crawler
    {
        return $this->browser->request('GET', '/account/profile');
    }

    private static function reread(User $user): User
    {
        $reread = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id);
        static::assertInstanceOf(User::class, $reread);

        return $reread;
    }
}
