<?php

declare(strict_types=1);

/*
 * Model half of "castor saml-sp": SimpleSAMLphp's AuthnRequests received and validated (spec/saml.md section 6.8).
 */

use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedAuthnRequest;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Psr\Clock\ClockInterface;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * @throws RuntimeException
 */
function captured(string $directory, string $name): string
{
    $contents = file_get_contents($directory . '/' . $name);
    if ($contents === false) {
        throw new RuntimeException(sprintf('%s/%s cannot be read.', $directory, $name));
    }

    return $contents;
}

$directory = $argv[1] ?? null;
if ($directory === null || ! is_dir($directory)) {
    throw new InvalidArgumentException('usage: php tests/demo/saml-sp-model.php <directory of the captured documents>');
}

$clock = new class implements ClockInterface {
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
};
$loader = SamlLoader::create();
$reader = new MetadataReader($loader, $clock);

try {
    $provider = $reader->readTrusted($loader->load(captured(
        $directory,
        'idp-metadata.xml',
    )))->identityProvider ?? throw new RuntimeException('the metadata of the provider hold no identity provider');
    $descriptor = $reader->readTrusted($loader->load(captured($directory, 'sp-metadata.xml')));
    $serviceProvider = $descriptor->serviceProvider ?? throw new RuntimeException('the metadata of the service provider hold no service provider');
    $validator = new AuthnRequestValidator($loader, $clock);

    $received = [];
    if (is_file($directory . '/authn-request-redirect.url')) {
        $url = trim(captured($directory, 'authn-request-redirect.url'));
        $received[] = new RedirectReceiver($loader)->authnRequest((string) parse_url($url, \PHP_URL_QUERY));
    }
    if (is_file($directory . '/authn-request-post.fields.json')) {
        $fields = json_decode(captured($directory, 'authn-request-post.fields.json'), true, 4, \JSON_THROW_ON_ERROR);
        if (! is_array($fields)) {
            throw new RuntimeException('authn-request-post.fields.json does not hold the fields of a form');
        }
        $received[] = new PostReceiver($loader)->authnRequest($fields);
    }
    if ($received === []) {
        throw new RuntimeException('no AuthnRequest in ' . $directory);
    }

    foreach ($received as $request) {
        $accepted = $request->validate($validator, $serviceProvider, $provider, single_sign_on_location($provider->singleSignOnServices, $request));
        printf(
            "the model accepted the AuthnRequest %s of %s over %s (%s), issued %s, RelayState of %d bytes, asking for the assertion consumer service %s\n",
            $accepted->request->id,
            $descriptor->entityId,
            $request->binding->name,
            $accepted->authentication->name,
            $accepted->request->issueInstant->format('Y-m-d\TH:i:s\Z'),
            strlen((string) $request->relayState),
            $accepted->assertionConsumerService->location,
        );
    }
} catch (Throwable $throwable) {
    fwrite(\STDERR, sprintf("not accepted by the model: %s: %s\n", $throwable::class, $throwable->getMessage()));

    throw $throwable;
}

/**
 * @param list<Endpoint> $services
 *
 * @throws RuntimeException
 */
function single_sign_on_location(array $services, ReceivedAuthnRequest $request): string
{
    foreach ($services as $service) {
        if ($service->binding === $request->binding) {
            return $service->location;
        }
    }

    throw new RuntimeException(sprintf('the provider publishes no single sign-on service for %s', $request->binding->name));
}
