<?php

namespace Mh828\WebApisWebauthn\Abstracts;

abstract class PublicKeyCredentialResponse
{
    public string $attestationObject;
    public string $authenticatorData;
    public string $clientDataJSON;
    public string $publicKey;
    public int $publicKeyAlgorithm;
    public array $transports;
    public string $signature;
    public string $userHandle;
}