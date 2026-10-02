<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page where the signed-in user consults what this provider holds about them (architecture §5.2): the
 * account itself, which keeping a record keeps, and the claims of OIDC Core §5.1 they told us, each one
 * only when it is set.
 */
final class AccountProfileTest extends BrowserTestCase
{
    #[Test]
    public function thePageNeedsASessionOfTheCore(): void
    {
        // When
        $crawler = $this->browser->request('GET', '/account/profile');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertSame('login_required', $crawler->filter('p[data-error]')->attr('data-error'));
    }

    #[Test]
    public function thePageNamesTheAccountItself(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->profilePage();

        // Then
        self::assertInteractionHeaders($this->browser->getResponse());
        static::assertSame('alice', $crawler->filter('dl[data-information="account"] dd[data-detail="username"]')->text());
        static::assertSame('alice-subject', $crawler->filter('dd[data-detail="subject"]')->text());
        static::assertNotSame('', $crawler->filter('dd[data-detail="created_at"] time')->attr('datetime'));
    }

    #[Test]
    public function thePageSaysSoWhenTheRecordHoldsNothingOfThePerson(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->profilePage();

        // Then
        static::assertCount(1, $crawler->filter('p[data-claims="none"]'));
        static::assertCount(0, $crawler->filter('dl[data-information="claims"]'));
    }

    #[Test]
    public function thePageListsEveryClaimTheRecordHolds(): void
    {
        // Given
        $this->signIn($this->described(self::user('alice')));

        // When
        $crawler = $this->profilePage();

        // Then
        $claims = $crawler->filter('dl[data-information="claims"] dd');
        static::assertSame(
            ['email', 'phone_number', 'name', 'given_name', 'family_name', 'locale', 'address'],
            $claims->extract(['data-detail']),
        );
        static::assertSame('Alice Example', $crawler->filter('dd[data-detail="name"]')->text());
        static::assertSame('12 Baker Street, NW1, London', $crawler->filter('dd[data-detail="address"]')->text());
    }

    /**
     * OIDC Core §5.1: a contact detail is either one this provider has verified or one it has not, and the
     * page says which.
     */
    #[Test]
    #[DataProvider('provideVerifications')]
    public function thePageSaysWhetherTheEmailAddressIsVerified(bool $verified, string $expected): void
    {
        // Given
        $user = self::user('alice');
        $user->changeEmail(new EmailAddress('alice@beffroi.test'), $verified, self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($user);
        $this->signIn($user);

        // When
        $crawler = $this->profilePage();

        // Then
        static::assertSame($expected, $crawler->filter('dd[data-detail="email"] span[data-verified]')->attr('data-verified'));
    }

    /**
     * @return iterable<string, array{bool, string}>
     */
    public static function provideVerifications(): iterable
    {
        yield 'verified' => [true, 'yes'];
        yield 'not verified' => [false, 'no'];
    }

    #[Test]
    public function thePageOffersTheWayBackToTheHomeOfTheAccount(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->profilePage();

        // Then
        static::assertSame('/account', $crawler->filter('nav a[data-back]')->attr('href'));
    }

    /**
     * A user who told the provider about themselves: a contact detail of each kind, three claims of the
     * profile and an address of its parts.
     */
    private function described(User $user): User
    {
        $now = new DateTimeImmutable('2026-01-15 10:00:00');
        $user->changeEmail(new EmailAddress('alice@beffroi.test'), true, $now);
        $user->changePhoneNumber('+33123456789', false, $now);
        $user->updateProfile(new Profile(
            name: 'Alice Example',
            givenName: 'Alice',
            familyName: 'Example',
            locale: 'en',
        ), $now);
        $user->changeAddress(new Address(
            streetAddress: '12 Baker Street',
            locality: 'London',
            postalCode: 'NW1',
        ), $now);
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($user);

        return $user;
    }

    private function profilePage(): Crawler
    {
        $crawler = $this->browser->request('GET', '/account/profile');
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }
}
