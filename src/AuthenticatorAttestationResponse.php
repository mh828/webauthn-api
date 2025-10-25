<?php

namespace Mh828\WebApisWebauthn;

use Mh828\WebApisWebauthn\Abstracts\PublicKeyCredential;
use Mh828\WebApisWebauthn\Enums\PublicKeyAlgorithms;
use Mh828\WebApisWebauthn\Helpers\General;

class AuthenticatorAttestationResponse extends PublicKeyCredential
{
    public const PREFERRED_ALGORITHM = PublicKeyAlgorithms::RS256;


    /**
     * @return \stdClass|null
     */
    public function getCredential(): ?\stdClass
    {
        return $this->credential;
    }

    public function getPublicKeyAlgorithm(): ?PublicKeyAlgorithms
    {
        return PublicKeyAlgorithms::tryFrom($this->response->publicKeyAlgorithm);
    }

    public function getOpenSSLEquivalenceAlgorithm(): ?int
    {
        return match ($this->getPublicKeyAlgorithm()) {
            PublicKeyAlgorithms::ES256 => OPENSSL_ALGO_SHA256,
            PublicKeyAlgorithms::RS256 => OPENSSL_ALGO_SHA256,
            default => null
        };
    }

    public function getPublicKey(): \OpenSSLAsymmetricKey|false
    {
        return openssl_pkey_get_public(
            "-----BEGIN PUBLIC KEY-----\n" .
            base64_encode(General::base64_decode_url($this->response->publicKey)) .
            "\n-----END PUBLIC KEY-----"
        );
    }


    public static function publicKeyCreationOptions(string $challenge,
                                                    string $host, string $hostName,
                                                           $userId, $userName, $userDisplayName): string
    {
        return json_encode([
            'challenge' => General::base64_encode_url($challenge),
            'rp' => ['id' => $host, 'name' => $hostName],
            'user' => ['id' => General::base64_encode_url($userId), 'name' => $userName, 'displayName' => $userDisplayName],
            'pubKeyCredParams' => [
                ["type" => 'public-key', 'alg' => PublicKeyAlgorithms::RS256->value],
                ["type" => 'public-key', 'alg' => PublicKeyAlgorithms::ES256->value],
            ],
            'timeout' => 120000,
            'attestation' => "none",
            'authenticatorSelection' => [
                'requireResidentKey' => true,
                'residentKey' => 'required',
                'userVerification' => 'preferred',
                'authenticatorAttachment' => "platform"
            ]
        ]);
    }
}
