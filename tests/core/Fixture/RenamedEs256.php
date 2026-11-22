<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function array_values;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;

final readonly class RenamedEs256 implements SignatureAlgorithm
{
    private ES256 $es256;

    public function __construct(
        private string $name,
    ) {
        $this->es256 = new ES256();
    }

    public function name(): string
    {
        return $this->name;
    }

    /**
     * @return list<string>
     */
    public function allowedKeyTypes(): array
    {
        return array_values($this->es256->allowedKeyTypes());
    }

    public function sign(JWK $key, string $input): string
    {
        return $this->es256->sign($key, $input);
    }

    public function verify(JWK $key, string $input, string $signature): bool
    {
        return $this->es256->verify($key, $input, $signature);
    }
}
