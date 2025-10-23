<?php

namespace Mh828\WebApisWebauthn\Helpers;

/**
 * @method static base64_encode_url($string): string
 * @method static base64_decode_url($string): string
 */
class General
{
    private static ?self $instance = null;

    public static function __callStatic($name, $arguments): mixed
    {
        if (!self::$instance) self::$instance = new static();
        if (method_exists(self::$instance, '_' . $name))
            return call_user_func_array([self::$instance, '_' . $name], $arguments);

        return null;
    }

    function _base64_encode_url($string): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($string));
    }

    function _base64_decode_url($string): string
    {
        return base64_decode(str_replace(['-', '_'], ['+', '/'], $string));
    }
}