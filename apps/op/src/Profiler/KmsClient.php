<?php

declare(strict_types=1);

namespace App\Profiler;

/**
 * Which KMS client the deployment opens its envelopes with, by the name it carries in
 * "key_management.clients", the configuration of KeyManagementBundle, and by nothing else.
 *
 * A name is what an operator wrote and what the framework's own KMS panel lists the client under, so
 * the two panels say the same word of the same client. It is also all the panel needs to say: what
 * the client is made of, one provider or several, and the DSN of each, are the business of that other
 * panel, and a DSN may carry a credential or a key identifier that a panel printing it would publish
 * to whoever opens the profiler.
 */
final readonly class KmsClient
{
    public function __construct(
        private string $name,
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }
}
