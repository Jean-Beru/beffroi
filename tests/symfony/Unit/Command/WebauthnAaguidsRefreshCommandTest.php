<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Command;

use App\Command\WebauthnAaguidsRefreshCommand;
use App\Webauthn\DocumentDownload;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticatorListStore;
use Beffroi\Core\Tests\Fixture\AuthenticatorLists;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_replace;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Architecture §5.5: the list of passkey providers the community keeps, downloaded by hand, read as that list
 * and stored; a list refused keeps nothing and leaves the stored one as it was.
 */
final class WebauthnAaguidsRefreshCommandTest extends TestCase
{
    private InMemoryAuthenticatorListStore $store;

    protected function setUp(): void
    {
        $this->store = new InMemoryAuthenticatorListStore();
    }

    #[Test]
    public function theListOfTheCommunityIsDownloadedReadAndStored(): void
    {
        // Given
        $list = AuthenticatorLists::document([
            '50726f74-6f6e-5061-7373-50726f746f6e' => AuthenticatorLists::model('Proton Pass'),
            'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4' => AuthenticatorLists::model('Google Password Manager'),
        ]);
        $requests = [];
        $tester = $this->refresh(new MockHttpClient(static function (string $method, string $url) use ($list, &$requests): MockResponse {
            $requests[] = $url;

            return new MockResponse($list);
        }));

        // When
        $tester->execute([]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame([WebauthnAaguidsRefreshCommand::COMMUNITY_LIST], $requests);
        static::assertSame($list, $this->store->read());
        static::assertStringContainsString(
            'The list of ' . WebauthnAaguidsRefreshCommand::COMMUNITY_LIST . ' is stored: it names 2 authenticators.',
            self::flattened($tester),
        );
    }

    #[Test]
    public function aMirrorIsDownloadedWhenItsUrlIsGiven(): void
    {
        // Given
        $requests = [];
        $tester = $this->refresh(new MockHttpClient(static function (string $method, string $url) use (&$requests): MockResponse {
            $requests[] = $url;

            return new MockResponse(AuthenticatorLists::document([
                '9ddd1817-af5a-4672-a2b9-3e3dd95000a9' => AuthenticatorLists::model('Windows Hello'),
            ]));
        }));

        // When
        $tester->execute([
            '--url' => 'https://mirror.example/aaguid.json',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame(['https://mirror.example/aaguid.json'], $requests);
    }

    /**
     * The README of the list says a retired list becomes an empty object: it is no reason to forget the names
     * the deployment holds.
     */
    #[Test]
    public function anEmptyListIsRefusedAndTheStoredOneStays(): void
    {
        // Given
        $stored = AuthenticatorLists::document(['9ddd1817-af5a-4672-a2b9-3e3dd95000a9' => AuthenticatorLists::model('Windows Hello')]);
        $this->store->write($stored);
        $tester = $this->refresh(new MockHttpClient([new MockResponse('{}')]));

        // When
        $tester->execute([]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame($stored, $this->store->read());
        static::assertStringContainsString(
            'is refused, nothing of it is kept and the stored one stays: it names no authenticator, which is what a retired list becomes',
            self::flattened($tester),
        );
    }

    #[Test]
    public function aDocumentThatIsNotTheListIsRefusedAndNothingIsStored(): void
    {
        // Given
        $tester = $this->refresh(new MockHttpClient([new MockResponse('<html>Not found</html>')]));

        // When
        $tester->execute([]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertNull($this->store->read());
        static::assertStringContainsString('is refused, nothing of it is kept and the stored one stays: it is not JSON', self::flattened($tester));
    }

    /**
     * Decision 0006: no outbound request follows a redirect; the URL the service redirects to is named.
     */
    #[Test]
    public function aServiceThatRedirectsIsRefusedWithTheUrlItNames(): void
    {
        // Given
        $tester = $this->refresh(new MockHttpClient([new MockResponse('', [
            'http_code' => 301,
            'response_headers' => [
                'location' => 'https://elsewhere.example/aaguid.json',
            ],
        ])]));

        // When
        $tester->execute([]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertNull($this->store->read());
        static::assertStringContainsString(
            'the service redirects to https://elsewhere.example/aaguid.json, and no outbound request follows a redirect; name that URL instead',
            self::flattened($tester),
        );
    }

    private function refresh(MockHttpClient $http): CommandTester
    {
        return new CommandTester(new Command('beffroi:webauthn:aaguids-refresh')->setCode(
            new WebauthnAaguidsRefreshCommand(new DocumentDownload($http), $this->store),
        ));
    }

    private static function flattened(CommandTester $tester): string
    {
        $display = preg_replace('/\s*\n\s*!?\s*/', ' ', $tester->getDisplay(true));
        static::assertIsString($display);

        return $display;
    }
}
