<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Identity\PushSubscription;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 8030 §2, RFC 8291 §3.1, RFC 8292 §3.2: what a browser hands over when it subscribes, and what this
 * provider refuses to keep as a subscription.
 */
final class PushSubscriptionTest extends TestCase
{
    private const string ENDPOINT = 'https://push.example/f/AbCdEf';

    private const string PUBLIC_KEY = 'BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM';

    private const string AUTH_SECRET = 'tBHItJI5svbpez7KI4CCXg';

    /**
     * What the same browser hands over the next time it subscribes: a browser draws both afresh every time
     * (RFC 8291 §3.1).
     */
    private const string OTHER_PUBLIC_KEY = 'BCmti7ScyxVpXpWiRsw88Bt4pPqoQfOF7pwoSHnt4V8MwHbDb-3sQd7mpE4tCLnfbEvJ6VPwxQEO-zPlRrLW4tI';

    private const string OTHER_AUTH_SECRET = 'BTBZMqHH6r4Tts7J_aSIgg';

    private User $alice;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user(Fixtures::tenant());
    }

    /**
     * Decision 0002: the tenant of a subscription is the tenant of the user it belongs to, restated.
     */
    #[Test]
    public function itBelongsToTheTenantOfItsUser(): void
    {
        // When
        $subscription = $this->subscription();

        // Then
        static::assertTrue($subscription->tenant->equals($this->alice->tenant));
    }

    /**
     * A browser is recognised by the digest of its endpoint, whatever its length.
     */
    #[Test]
    public function itIsRecognisedByTheDigestOfItsEndpoint(): void
    {
        // When / Then
        static::assertSame(PushSubscription::digestOf(self::ENDPOINT), $this->subscription()->endpointHash);
    }

    /**
     * RFC 8030 §2: a push service takes a message over HTTPS, and nothing else is an endpoint.
     */
    #[Test]
    public function anEndpointThatIsNotHttpsIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A push subscription is delivered to over HTTPS (RFC 8030 section 2).');

        // When
        $this->subscription(endpoint: 'http://push.example/f/AbCdEf');
    }

    /**
     * RFC 8291 §3.1: the two keys arrive base64url, and what is not is not a key of a browser.
     */
    #[Test]
    #[DataProvider('provideKeysThatAreNotBase64Url')]
    public function aKeyThatIsNotBase64UrlIsRefused(string $publicKey, string $authSecret, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->subscription(publicKey: $publicKey, authSecret: $authSecret);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideKeysThatAreNotBase64Url(): iterable
    {
        yield 'a public key with padding' => [
            self::PUBLIC_KEY . '==',
            self::AUTH_SECRET,
            'The public key of a push subscription is base64url (RFC 8291 section 3.1).',
        ];
        yield 'an empty public key' => [
            '',
            self::AUTH_SECRET,
            'The public key of a push subscription is base64url (RFC 8291 section 3.1).',
        ];
        yield 'an authentication secret in standard base64' => [
            self::PUBLIC_KEY,
            'tBHItJI5svbpez7KI4CC+g',
            'The authentication secret of a push subscription is base64url (RFC 8291 section 3.1).',
        ];
    }

    /**
     * RFC 8292 §3.2: a subscription is bound to the application server key it was made under, so one
     * that names none is one nobody could sign a push for.
     */
    #[Test]
    public function itNamesTheApplicationServerKeyItWasMadeUnder(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A push subscription names the application server key it was made under (RFC 8292 section 3.2).');

        // When
        $this->subscription(kid: '');
    }

    /**
     * RFC 8292 §4.2: a push signed by another key is refused by the push service, so the key a
     * subscription names is the only one that may sign for it.
     */
    #[Test]
    public function itIsBoundToOneKeyAndNotToAnother(): void
    {
        // Given
        $subscription = $this->subscription(kid: 'the-key');

        // When / Then
        static::assertTrue($subscription->isBoundTo('the-key'));
        static::assertFalse($subscription->isBoundTo('another-key'));
    }

    /**
     * The row stays, as it does for every credential of a user, and the first revocation wins.
     */
    #[Test]
    public function aRevokedSubscriptionKeepsTheDateOfTheFirstRevocation(): void
    {
        // Given
        $subscription = $this->subscription();
        $subscription->revoke(Fixtures::now());

        // When
        $subscription->revoke(Fixtures::now()->modify('+1 hour'));

        // Then
        static::assertTrue($subscription->isRevoked());
        static::assertEquals(Fixtures::now(), $subscription->revokedAt);
    }

    /**
     * Push API §3.4, RFC 8291 §3.1: a browser that subscribes again draws its keys afresh and may have
     * been handed another application server key since, and this row is what carries them.
     */
    #[Test]
    public function aBrowserThatSubscribesAgainCarriesWhatItHandedThisTime(): void
    {
        // Given
        $subscription = $this->subscription();

        // When
        $subscription->resubscribedWith(self::OTHER_PUBLIC_KEY, self::OTHER_AUTH_SECRET, 'the-other-key', 'Alice at home');

        // Then
        static::assertSame(self::OTHER_PUBLIC_KEY, $subscription->publicKey);
        static::assertSame(self::OTHER_AUTH_SECRET, $subscription->authSecret);
        static::assertTrue($subscription->isBoundTo('the-other-key'));
        static::assertSame('Alice at home', $subscription->label);
    }

    /**
     * RFC 8030 §7.3: a browser the user had taken out says it is reachable again by subscribing again.
     */
    #[Test]
    public function aBrowserTakenOutIsReachableAgainWhenItSubscribesAgain(): void
    {
        // Given
        $subscription = $this->subscription();
        $subscription->revoke(Fixtures::now());

        // When
        $subscription->resubscribedWith(self::OTHER_PUBLIC_KEY, self::OTHER_AUTH_SECRET, 'the-key', null);

        // Then
        static::assertFalse($subscription->isRevoked());
    }

    /**
     * What the second way in records is what the first one accepts, and nothing else.
     */
    #[Test]
    public function aBrowserThatSubscribesAgainWithAKeyThatIsNotBase64UrlIsRefused(): void
    {
        // Given
        $subscription = $this->subscription();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The public key of a push subscription is base64url (RFC 8291 section 3.1).');

        // When
        $subscription->resubscribedWith('not base64url', self::OTHER_AUTH_SECRET, 'the-key', null);
    }

    /**
     * The name of a browser is its holder's, and theirs to correct: architecture §5.2.
     */
    #[Test]
    public function itIsNamedAgainByItsHolder(): void
    {
        // Given
        $subscription = $this->subscription();

        // When
        $subscription->rename('  Alice at home  ');

        // Then
        static::assertSame('Alice at home', $subscription->label);
    }

    /**
     * What a browser may be called is the length of the column that holds it, and never nothing: a line
     * nobody can tell from another is what naming one is for.
     */
    #[Test]
    #[DataProvider('provideNamesABrowserDoesNotHold')]
    public function aNameABrowserDoesNotHoldIsRefused(string $label): void
    {
        // Given
        $subscription = $this->subscription();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The name of a browser is 1 to 255 characters long.');

        // When
        $subscription->rename($label);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesABrowserDoesNotHold(): iterable
    {
        yield 'empty' => [''];
        yield 'blank' => ['   '];
        yield 'longer than the column' => [str_repeat('a', PushSubscription::LABEL_MAX_LENGTH + 1)];
    }

    /**
     * Nothing of what a push is sent under moves when the name does.
     */
    #[Test]
    public function namingItLeavesWhatTheBrowserHandedOver(): void
    {
        // Given
        $subscription = $this->subscription();

        // When
        $subscription->rename('Alice at home');

        // Then
        static::assertSame(self::PUBLIC_KEY, $subscription->publicKey);
        static::assertSame(self::AUTH_SECRET, $subscription->authSecret);
        static::assertSame('the-key', $subscription->applicationServerKid);
    }

    private function subscription(
        string $endpoint = self::ENDPOINT,
        string $publicKey = self::PUBLIC_KEY,
        string $authSecret = self::AUTH_SECRET,
        string $kid = 'the-key',
    ): PushSubscription {
        return new PushSubscription(
            Uuid::v7(),
            $this->alice,
            $endpoint,
            $publicKey,
            $authSecret,
            $kid,
            'Alice at the counter',
            Fixtures::now(),
        );
    }
}
