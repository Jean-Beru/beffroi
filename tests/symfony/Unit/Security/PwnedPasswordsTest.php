<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Security;

use App\Security\PwnedPasswords;
use Beffroi\Core\Domain\Credential\PasswordDigest;
use Beffroi\Core\Exception\BreachLookupFailedException;
use function implode;
use function is_array;
use function is_string;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * The list of compromised passwords read over the range endpoint (Pwned Passwords, range API): five
 * hexadecimal characters leave, the comparison of the thirty-five that are left is here.
 *
 * No test of any suite reaches the network: the client is a MockHttpClient, and the endpoint a deployment
 * does not name is the empty one, which asks nobody.
 */
final class PwnedPasswordsTest extends TestCase
{
    private const string ENDPOINT = 'https://list.example/range/';

    /**
     * The known SHA-1 of "password": bucket "5BAA6", suffix "1E4C9B93F3F0682250B6CF8331B7EE68FD8".
     */
    private const string PASSWORD = 'password';

    private const string PASSWORD_SUFFIX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';

    /**
     * The URL of the last request the client was asked for, null until one was made.
     */
    private ?string $urlAsked = null;

    /**
     * The headers of the last request, as the client normalised them.
     *
     * @var list<string>
     */
    private array $headersAsked = [];

    #[Test]
    public function theBucketOfTheDigestIsWhatIsAskedFor(): void
    {
        // Given
        $breaches = $this->breaches(self::answer([self::PASSWORD_SUFFIX => 2]));

        // When
        $breaches->timesSeen(PasswordDigest::of(self::PASSWORD));

        // Then
        static::assertSame('https://list.example/range/5BAA6', $this->urlAsked);
    }

    /**
     * The answer is asked padded, so that its length says nothing of the bucket either.
     */
    #[Test]
    public function theAnswerIsAskedPadded(): void
    {
        // Given
        $breaches = $this->breaches(self::answer([self::PASSWORD_SUFFIX => 2]));

        // When
        $breaches->timesSeen(PasswordDigest::of(self::PASSWORD));

        // Then
        static::assertContains('Add-Padding: true', $this->headersAsked);
    }

    /**
     * Decision 0006: no outbound request follows a redirect, and the client is told so, a redirect of the
     * endpoint being then an answer that is not a success (`a redirection nobody followed` below).
     */
    #[Test]
    public function theEndpointIsAskedWithoutFollowingARedirect(): void
    {
        // Given
        $response = self::answer([self::PASSWORD_SUFFIX => 2]);
        $breaches = $this->breaches($response);

        // When
        $breaches->timesSeen(PasswordDigest::of(self::PASSWORD));

        // Then
        static::assertSame(0, $response->getRequestOptions()['max_redirects'] ?? null);
    }

    #[Test]
    public function aSuffixTheBucketCountsIsTheCountOfTheDigest(): void
    {
        // Given
        $breaches = $this->breaches(self::answer([
            str_repeat('A', 35) => 7,
            self::PASSWORD_SUFFIX => 42,
        ]));

        // When
        $count = $breaches->timesSeen(PasswordDigest::of(self::PASSWORD));

        // Then
        static::assertSame(42, $count->times);
        static::assertTrue($count->isBreached());
    }

    /**
     * A bucket that holds other suffixes and not this one says the password is not in the list, which is
     * an answer and not an unknown.
     */
    #[Test]
    public function aBucketWithoutTheSuffixCountsNothing(): void
    {
        // Given
        $breaches = $this->breaches(self::answer([str_repeat('A', 35) => 7]));

        // When
        $count = $breaches->timesSeen(PasswordDigest::of(self::PASSWORD));

        // Then
        static::assertTrue($count->wasAsked());
        static::assertFalse($count->isBreached());
        static::assertSame(0, $count->times);
    }

    /**
     * The padding entries of a padded answer are counted zero and are read as any other line.
     */
    #[Test]
    public function aPaddingEntryCountedZeroIsNotABreach(): void
    {
        // Given
        $breaches = $this->breaches(self::answer([self::PASSWORD_SUFFIX => 0]));

        // When
        $count = $breaches->timesSeen(PasswordDigest::of(self::PASSWORD));

        // Then
        static::assertFalse($count->isBreached());
    }

    /**
     * A lower-case answer is the same answer: the endpoint writes upper case and nothing is refused for
     * the case of what it wrote.
     */
    #[Test]
    public function aLowerCaseAnswerIsReadAllTheSame(): void
    {
        // Given
        $breaches = $this->breaches(new MockResponse('1e4c9b93f3f0682250b6cf8331b7ee68fd8:3'));

        // When
        $count = $breaches->timesSeen(PasswordDigest::of(self::PASSWORD));

        // Then
        static::assertSame(3, $count->times);
    }

    /**
     * Decision 0006: an unknown is not a count of zero, and it is not a boolean this provider casts.
     */
    #[Test]
    #[DataProvider('provideAnswersThatAreNoRange')]
    public function anAnswerThatIsNoRangeIsRefused(MockResponse $response, string $message): void
    {
        // Given
        $breaches = $this->breaches($response);

        // Then
        $this->expectException(BreachLookupFailedException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $breaches->timesSeen(PasswordDigest::of(self::PASSWORD));
    }

    /**
     * @return iterable<string, array{MockResponse, string}>
     */
    public static function provideAnswersThatAreNoRange(): iterable
    {
        yield 'a server error' => [
            new MockResponse('', ['http_code' => 503]),
            'The list of compromised passwords answered 503.',
        ];
        yield 'a redirection nobody followed' => [
            new MockResponse('', ['http_code' => 302]),
            'The list of compromised passwords answered 302.',
        ];
        yield 'an empty body' => [
            new MockResponse(''),
            'The list of compromised passwords answered an empty body.',
        ];
        yield 'a page of HTML' => [
            new MockResponse('<html lang="en"><body>Not here</body></html>'),
            'The list of compromised passwords answered a body that is not a range.',
        ];
        yield 'a suffix of the wrong length' => [
            new MockResponse('1E4C9B93F3F0682250B6CF8331B7EE68FD:3'),
            'The list of compromised passwords answered a body that is not a range.',
        ];
        yield 'a count that is no number' => [
            new MockResponse(self::PASSWORD_SUFFIX . ':many'),
            'The list of compromised passwords answered a body that is not a range.',
        ];
    }

    #[Test]
    public function aListThatCouldNotBeReachedIsRefused(): void
    {
        // Given
        $breaches = $this->breaches(new MockResponse(info: ['error' => 'timeout']));

        // Then
        $this->expectException(BreachLookupFailedException::class);
        $this->expectExceptionMessageIs('The list of compromised passwords could not be reached.');

        // When
        $breaches->timesSeen(PasswordDigest::of(self::PASSWORD));
    }

    /**
     * A deployment that names no endpoint asks nobody: it poses passwords and signs people in on the
     * rules of the core alone, as one that names no GeoIP licence key says an address and no place.
     */
    #[Test]
    public function aDeploymentThatNamesNoEndpointLooksNothingUp(): void
    {
        // Given
        $breaches = new PwnedPasswords(new MockHttpClient(static function (): MockResponse {
            TestCase::fail('A deployment that names no endpoint asks nobody.');
        }));

        // When
        $count = $breaches->timesSeen(PasswordDigest::of(self::PASSWORD));

        // Then
        static::assertFalse($breaches->looksUp());
        static::assertFalse($count->wasAsked());
    }

    /**
     * An endpoint written with or without its trailing slash addresses the same bucket.
     */
    #[Test]
    #[DataProvider('provideEndpoints')]
    public function theBucketIsAppendedToTheEndpointAsWritten(string $endpoint): void
    {
        // Given
        $breaches = $this->breaches(self::answer([self::PASSWORD_SUFFIX => 1]), $endpoint);

        // When
        $breaches->timesSeen(PasswordDigest::of(self::PASSWORD));

        // Then
        static::assertSame('https://list.example/range/5BAA6', $this->urlAsked);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideEndpoints(): iterable
    {
        yield 'with a trailing slash' => ['https://list.example/range/'];
        yield 'without one' => ['https://list.example/range'];
    }

    /**
     * @param array<string, int> $counted
     */
    private static function answer(array $counted): MockResponse
    {
        $lines = [];
        foreach ($counted as $suffix => $times) {
            $lines[] = $suffix . ':' . $times;
        }

        return new MockResponse(implode("\r\n", $lines));
    }

    /**
     * The bridge over a client that answers this and writes down what it was asked.
     */
    private function breaches(MockResponse $response, string $endpoint = self::ENDPOINT): PwnedPasswords
    {
        $client = new MockHttpClient(function (string $method, string $url, array $options) use ($response): MockResponse {
            $this->urlAsked = $url;
            $this->headersAsked = self::headersOf($options);

            return $response;
        });

        return new PwnedPasswords($client, $endpoint);
    }

    /**
     * @param array<array-key, mixed> $options
     *
     * @return list<string>
     */
    private static function headersOf(array $options): array
    {
        $headers = $options['headers'] ?? null;
        if (! is_array($headers)) {
            return [];
        }
        $written = [];
        foreach ($headers as $header) {
            if (is_string($header)) {
                $written[] = $header;
            }
        }

        return $written;
    }
}
