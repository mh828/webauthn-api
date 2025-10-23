<?php

namespace Mh828\WebApisWebauthn\Enums;

enum PublicKeyAlgorithms: int
{
    case  EdDSA = -8;
    case ES256 = -7;
    case RS256 = -257;
}
