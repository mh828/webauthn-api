<?php

namespace Mh828\WebApisWebauthn\Abstracts;

/**
 * @property-read string $type;
 * @property-read string $challenge;
 * @property-read bool $crossOrigin;
 * @property-read string $topOrigin;
 * @property-read string $origin;
 * @property-read mixed $tokenBinding;
 */
class ResponseClientDataJSON
{
    private ?\stdClass $jsonData;

    public function __construct(public $jsonString)
    {
        $this->jsonData = json_decode($this->jsonString);
    }

    public function __get(string $name)
    {
        return $this->jsonData->$name ?? null;
    }

    /**
     * @return \stdClass|null
     */
    public function getJsonData(): ?\stdClass
    {
        return $this->jsonData;
    }

}