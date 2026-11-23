<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\PrivateNetworkGuard;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Decision 0006
 */
final class PrivateNetworkGuardTest extends TestCase
{
    #[Test]
    #[DataProvider('provideAddressesOfTheDeployment')]
    public function aRequestToAnAddressOfThePrivateNetworksIsRefused(string $url, string $host): void
    {
        // Given
        $client = new PrivateNetworkGuard([])->guard(new MockHttpClient(new MockResponse('[]')));

        // Then
        $this->expectException(TransportException::class);
        $this->expectExceptionMessageIs(sprintf('Host "%s" is blocked for "%s".', $host, $url));

        // When
        $client->request('GET', $url);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideAddressesOfTheDeployment(): iterable
    {
        yield 'a private address' => ['https://10.0.0.5:8443/x', '10.0.0.5'];
        yield 'another private address' => ['https://192.168.1.1/', '192.168.1.1'];
        yield 'the metadata of a cloud' => ['https://169.254.169.254/latest/meta-data/', '169.254.169.254'];
        yield 'the loopback address' => ['http://127.0.0.1:2019/config/', '127.0.0.1'];
        yield 'the loopback address of IPv6' => ['http://[::1]:2019/config/', '[::1]'];
        yield 'a unique local address' => ['https://[fd00::1]/x', '[fd00::1]'];
        yield 'a link-local address of IPv6' => ['https://[fe80::1]/x', '[fe80::1]'];
        yield 'the loopback address mapped in IPv6' => ['https://[::ffff:127.0.0.1]/x', '[::ffff:127.0.0.1]'];
        yield 'the unspecified address' => ['https://0.0.0.0/x', '0.0.0.0'];
        yield 'a shared address of a carrier' => ['https://100.64.0.1/x', '100.64.0.1'];
        yield 'a name that resolves to the loopback address' => ['http://localhost:2019/config/', 'localhost'];
    }

    #[Test]
    public function aRequestToAPublicAddressGoesThrough(): void
    {
        // Given
        $client = new PrivateNetworkGuard([])->guard(new MockHttpClient(new MockResponse('[]')));

        // When
        $response = $client->request('GET', 'https://9.9.9.9/jwks');

        // Then
        static::assertSame(200, $response->getStatusCode());
    }

    #[Test]
    #[DataProvider('provideNetworksTheDeploymentNames')]
    public function aRequestToANetworkTheDeploymentNamesGoesThrough(string $network): void
    {
        // Given
        $client = new PrivateNetworkGuard([$network])->guard(new MockHttpClient(new MockResponse('[]')));

        // When
        $response = $client->request('GET', 'https://10.20.1.2/jwks');

        // Then
        static::assertSame(200, $response->getStatusCode());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNetworksTheDeploymentNames(): iterable
    {
        yield 'the network' => ['10.20.0.0/16'];
        yield 'the address alone' => ['10.20.1.2'];
    }

    #[Test]
    public function aNetworkTheDeploymentNamesReachesNoOther(): void
    {
        // Given
        $client = new PrivateNetworkGuard(['10.20.0.0/16'])->guard(new MockHttpClient(new MockResponse('[]')));

        // Then
        $this->expectException(TransportException::class);
        $this->expectExceptionMessageIs('Host "10.21.0.1" is blocked for "https://10.21.0.1/jwks".');

        // When
        $client->request('GET', 'https://10.21.0.1/jwks');
    }

    #[Test]
    #[DataProvider('provideWhatIsNoNetwork')]
    public function whatIsNeitherAnAddressNorANetworkIsRefused(string $network): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The "beffroi" configuration key "outbound.reachable_private_networks" names "%s", which is neither an IP address nor a network in CIDR notation.',
            $network,
        ));

        // When
        new PrivateNetworkGuard([$network]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNoNetwork(): iterable
    {
        yield 'a name' => ['intranet.example'];
        yield 'nothing' => [''];
        yield 'a prefix longer than IPv4 holds' => ['10.0.0.0/33'];
        yield 'a prefix longer than IPv6 holds' => ['fd00::/129'];
        yield 'no prefix after the slash' => ['10.0.0.0/'];
        yield 'a prefix that is no number' => ['10.0.0.0/eight'];
        yield 'a prefix and a line feed' => ["10.0.0.0/8\n"];
    }

    #[Test]
    public function itKeepsTheNetworksItIsGiven(): void
    {
        // When / Then
        static::assertSame(
            ['10.0.0.0/8', 'fd00::/8', '192.168.1.10', '::1'],
            new PrivateNetworkGuard(['10.0.0.0/8', 'fd00::/8', '192.168.1.10', '::1'])->reachable,
        );
    }
}
