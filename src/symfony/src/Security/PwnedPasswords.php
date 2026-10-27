<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Beffroi\Bundle\Http\Timeout;
use Beffroi\Core\Domain\Credential\BreachCount;
use Beffroi\Core\Domain\Credential\PasswordDigest;
use Beffroi\Core\Exception\BreachLookupFailedException;
use Beffroi\Core\Port\BreachedPasswordsInterface;
use function explode;
use function hash_equals;
use function preg_match;
use function rtrim;
use SensitiveParameter;
use function sprintf;
use function strtoupper;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use function trim;

/**
 * The list of compromised passwords read over the range endpoint of Pwned Passwords (architecture §3.4):
 * five hexadecimal characters of the SHA-1 leave, the endpoint answers every suffix it counts under them,
 * and the comparison is here. No API key, no subscription, no account.
 *
 * **What leaves is a bucket and not a password.** The prefix names about a million passwords; the endpoint
 * learns which bucket was asked about and never which of its passwords, and nothing of the user who typed
 * it goes with the request. The answer is asked padded ("Add-Padding"), so that the length of the response
 * does not say how many suffixes the bucket really held either; the padding entries are counted zero and
 * are read as any other line.
 *
 * **A deployment that names no endpoint asks nothing.** It poses passwords and signs people in, which is
 * said where it is configured (PasswordsSection), as a deployment that names no GeoIP licence key serves
 * every flow with a provenance that says an address and no place rather than pretending to one. There is
 * no option in between and no second adapter to alias; the core keeps a null one for whoever wires the
 * core by hand.
 *
 * **An unknown is not a count of zero** (decision 0006). A timeout, a status that is not a success and a
 * body that does not read as counted suffixes are all the exception of the port, and each caller says what
 * it makes of one.
 */
final readonly class PwnedPasswords implements BreachedPasswordsInterface
{
    /**
     * Where Pwned Passwords serves the ranges (https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange),
     * for a deployment to write rather than a default to inherit.
     */
    public const string RANGE_ENDPOINT = 'https://api.pwnedpasswords.com/range/';

    /**
     * One line of the answer: the thirty-five characters that are left of the digest, and how many times
     * the list counts the password they complete.
     */
    private const string COUNTED_SUFFIX = '/^([0-9A-F]{35}):([0-9]+)$/';

    public function __construct(
        private HttpClientInterface $http,
        private string $endpoint = '',
        private Timeout $timeout = new Timeout(2.0),
    ) {
    }

    public function looksUp(): bool
    {
        return $this->endpoint !== '';
    }

    public function timesSeen(#[SensitiveParameter] PasswordDigest $digest): BreachCount
    {
        if (! $this->looksUp()) {
            return BreachCount::nothingAsked();
        }

        return BreachCount::times(self::countIn($this->answer($digest->prefix()), $digest->suffix()));
    }

    /**
     * @throws BreachLookupFailedException
     */
    private function answer(string $prefix): string
    {
        try {
            $response = $this->http->request('GET', rtrim($this->endpoint, '/') . '/' . $prefix, [
                'headers' => [
                    // the answer padded with suffixes counted zero, so that its length says nothing of the
                    // bucket either
                    'Add-Padding' => 'true',
                    'Accept' => 'text/plain',
                ],
                ...$this->timeout->options(),
            ]);
            $status = $response->getStatusCode();
            if ($status !== 200) {
                throw new BreachLookupFailedException(sprintf('The list of compromised passwords answered %d.', $status));
            }

            return $response->getContent(false);
        } catch (HttpExceptionInterface $exception) {
            throw new BreachLookupFailedException('The list of compromised passwords could not be reached.', 0, $exception);
        }
    }

    /**
     * How many times the bucket counts the suffix, zero when it does not hold it.
     *
     * @throws BreachLookupFailedException when a line of the body is not a counted suffix, which is an
     *                                     answer from something that is not this endpoint
     */
    private static function countIn(string $body, #[SensitiveParameter] string $suffix): int
    {
        $counted = 0;
        $lines = 0;
        foreach (explode("\n", $body) as $line) {
            $line = strtoupper(trim($line));
            if ($line === '') {
                continue;
            }
            if (preg_match(self::COUNTED_SUFFIX, $line, $matches) !== 1) {
                throw new BreachLookupFailedException('The list of compromised passwords answered a body that is not a range.');
            }
            ++$lines;
            if (hash_equals($suffix, $matches[1])) {
                $counted = (int) $matches[2];
            }
        }
        if ($lines === 0) {
            throw new BreachLookupFailedException('The list of compromised passwords answered an empty body.');
        }

        return $counted;
    }
}
