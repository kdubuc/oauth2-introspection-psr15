# OAuth2 Introspection PSR-15 Middleware

Protect your API with OAuth 2.0 Token Introspection [RFC 7662](https://tools.ietf.org/html/rfc7662).

[PSR-6](https://www.php-fig.org/psr/psr-6/) can be used to store introspection data during its lifetime (if expiration timestamp of the token is specified by introspection endpoint).

## Install

Via Composer

``` bash
$ composer require kdubuc/oauth2-introspection-psr15
```

## Usage

```php
$middleware =  new Oauth2Introspection($http_psr18_client, $http_stream_psr17_factory, $http_request_psr17_factory, [
    'introspection_endpoint' => 'http://oauth2.example.com/introspect',
    'oauth2_client_id'       => 'client_id',
    'oauth2_client_secret'   => 'client_secret',
]);

$middleware->enableCache($psr6_cache);

// Introspection results will be stored into 'oauth2_access_token_introspection_data' request attribute
```

## Testing

``` bash
$ vendor/bin/phpunit tests/
```

## Contributing

Please see [CONTRIBUTING](.github/CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email kevindubuc62@gmail.com instead of using the issue tracker.

## Credits

- [Kévin DUBUC](https://github.com/kdubuc)
- [All Contributors](https://github.com/kdubuc/query-string-parser/graphs/contributors)

## License

The CeCILL-B License. Please see [License File](LICENSE.md) for more information.