<?php

namespace Mh828\WebApisWebauthn;

use Mh828\WebApisWebauthn\Enums\PublicKeyAlgorithms;
use Mh828\WebApisWebauthn\Helpers\General;
use Mh828\WebApisWebauthn\Abstracts\PublicKeyCredentialResponse;

/**
 * @property-read string $id
 * @property-read PublicKeyCredentialResponse $response
 * @property-read \stdClass $clientExtensionResults
 * @property-read string $type
 */
class AuthenticatorAttestationResponse
{
    private ?\stdClass $credential;
    public const PREFERRED_ALGORITHM = PublicKeyAlgorithms::RS256;

    public function __construct(public $responseJson)
    {
        $this->credential = json_decode($this->responseJson);
    }

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

    public function __get(string $name)
    {
        return $this->credential->$name ?? null;
    }

    public function getClientData()
    {
        return json_decode(General::base64_decode_url($this->response->clientDataJSON));
    }

    public function getPublicKey(): \OpenSSLAsymmetricKey|false
    {
        return openssl_pkey_get_public(
            "-----BEGIN PUBLIC KEY-----\n" .
            base64_encode(General::base64_decode_url($this->response->publicKey)) .
            "\n-----END PUBLIC KEY-----"
        );
    }

    public function isChallengeVerified($challenge): bool
    {
        return General::base64_encode_url($challenge) === ($this->getClientData()->challenge ?? null);
    }

    public static function publicKeyCreationOptions(string $challenge, string $host, string $hostName, $userId, $userName, $userDisplayName): string
    {
        return json_encode([
            'challenge' => General::base64_encode_url($challenge),
            'rp' => ['id' => $host, 'name' => $hostName],
            'user' => ['id' => General::base64_encode_url($userId), 'name' => $userName, 'displayName' => $userDisplayName],
            'pubKeyCredParams' => [["type" => 'public-key', 'alg' => self::PREFERRED_ALGORITHM->value]]
        ]);
    }
}