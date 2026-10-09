<?php

declare(strict_types=1);

namespace App\Demonstration;

use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Flow\FlowPicture;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\FlowPicturesInterface;
use function is_string;
use Symfony\Component\HttpFoundation\Request;

/**
 * Which flow a page of the demonstration was asked for (issue #462), read from the query: a grant type
 * is named by an absolute URI often enough that it travels as a parameter and not as a path.
 *
 * A name no wired grant gives itself is a flow this provider does not serve, and the page is a 404: the
 * set of pages is the set of pictures, which is the set of wired grants.
 */
final readonly class AskedFlow
{
    public const string PARAMETER = 'flow';

    public const string CLIENT_PARAMETER = 'client';

    public function __construct(
        private FlowPicturesInterface $pictures,
    ) {
    }

    /**
     * @throws InvalidArgumentException when the wiring does not hold together
     */
    public function picture(Request $request): ?FlowPicture
    {
        $asked = $request->query->get(self::PARAMETER);
        if (! is_string($asked) || $asked === '') {
            return null;
        }
        foreach ($this->pictures->pictures() as $picture) {
            if ($picture->grantType->value === $asked) {
                return $picture;
            }
        }

        return null;
    }

    /**
     * @throws InvalidArgumentException
     */
    public function grantType(Request $request): ?GrantTypeName
    {
        return $this->picture($request)?->grantType;
    }

    /**
     * The client whose trace of that flow is asked for, and null when the page is asked for the flow
     * alone: five rungs of a ladder are five clients of one flow.
     */
    public function client(Request $request): ?string
    {
        $asked = $request->query->get(self::CLIENT_PARAMETER);

        return is_string($asked) && $asked !== '' ? $asked : null;
    }
}
