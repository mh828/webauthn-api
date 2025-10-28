<?php

namespace Mh828\WebApisWebauthn;

use Mh828\WebApisWebauthn\Abstracts\PublicKeyCredential;
use Mh828\WebApisWebauthn\Enums\PublicKeyAlgorithms;
use Mh828\WebApisWebauthn\Helpers\General;

class AuthenticatorAssertionResponse extends PublicKeyCredential
{

    public function verifySignature(AuthenticatorAttestationResponse $publicKeyCredential): bool
    {
        return openssl_verify(
                General::base64_decode_url($this->response->authenticatorData) .
                openssl_digest(General::base64_decode_url($this->response->clientDataJSON), 'SHA256', true),
                General::base64_decode_url($this->response->signature),
                $publicKeyCredential->getPublicKey(),
                $publicKeyCredential->getOpenSSLEquivalenceAlgorithm() ?? OPENSSL_ALGO_SHA256
            ) === 1;
    }

    public static function publicKeyRequestionOptions(string $challenge,
                                                      string $host, array $allowCredentials = []): string
    {
        return json_encode([
            'challenge' => General::base64_encode_url($challenge),
            'rpId' => $host,
            'allowCredentials' => $allowCredentials
        ]);
    }
}