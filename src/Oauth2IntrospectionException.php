<?php

namespace Kdubuc\Middleware;

use Exception;

final class Oauth2IntrospectionException extends Exception
{
    public const AUTHORIZATION_HEADER_NOT_FOUND = 1;
    public const ACCESS_TOKEN_EMPTY             = 2;
    public const ACCESS_TOKEN_INVALID           = 3;
    public const ACCESS_TOKEN_INACTIVE          = 4;
    public const AUTHORIZATION_SERVER_ERROR     = 5;
    public const TOKEN_TYPE_HINT_UNKNOWN        = 6;
}
