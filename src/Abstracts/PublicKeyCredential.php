<?php

namespace Mh828\WebApisWebauthn\Abstracts;

use Mh828\WebApisWebauthn\Helpers\General;

/**
 * @property-read string $id
 * @property-read PublicKeyCredentialResponse $response
 * @property-read \stdClass $clientExtensionResults
 * @property-read string $type
 */
abstract class PublicKeyCredential
{
    private ?\stdClass $credential;

    public function __construct(public $responseJson)
    {
        $this->credential = json_decode($this->responseJson);
    }

    public function __get(string $name)
    {
        return $this->credential->$name ?? null;
    }

    public function getClientData(): ResponseClientDataJSON
    {
        return new ResponseClientDataJSON(General::base64_decode_url($this->response->clientDataJSON));
    }

    public function isChallengeVerified($challenge): bool
    {
        return General::base64_encode_url($challenge) === ($this->getClientData()->challenge ?? null);
    }

}