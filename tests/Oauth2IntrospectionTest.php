<?php

use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\HttpFactory;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\ResponseInterface;
use Kdubuc\Middleware\Oauth2Introspection;
use Psr\Http\Server\RequestHandlerInterface;
use WildWolf\Psr6MemoryCache as Psr6CacheTest;
use Kdubuc\Middleware\Oauth2IntrospectionException;

class Oauth2IntrospectionTest extends TestCase
{
    public const OAUTH2_CONFIG_EXAMPLE = [
        'introspection_endpoint' => 'http://oauth2.example.com/introspect',
        'oauth2_client_id'       => 'client_id',
        'oauth2_client_secret'   => 'client_secret',
    ];

    public const JWT_TEST = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

    public function testExceptionThrownWhenNoAuthorizationHeader()
    {
        $this->expectException(Oauth2IntrospectionException::class);
        $this->expectExceptionCode(Oauth2IntrospectionException::AUTHORIZATION_HEADER_NOT_FOUND);

        $http_factory     = new HttpFactory();
        $http_client_stub = $this->createStub(ClientInterface::class);
        $handler_stub     = $this->createStub(RequestHandlerInterface::class);
        $middleware       = new Oauth2Introspection($http_client_stub, $http_factory, $http_factory, self::OAUTH2_CONFIG_EXAMPLE);

        $server_request = $http_factory->createServerRequest('GET', 'http://example.com/userinfo');

        $middleware->process($server_request, $handler_stub);
    }

    public function testExceptionThrownWhenAccessTokenIsMalformed()
    {
        $this->expectException(Oauth2IntrospectionException::class);
        $this->expectExceptionCode(Oauth2IntrospectionException::ACCESS_TOKEN_INVALID);

        $http_factory     = new HttpFactory();
        $http_client_stub = $this->createStub(ClientInterface::class);
        $handler_stub     = $this->createStub(RequestHandlerInterface::class);
        $middleware       = new Oauth2Introspection($http_client_stub, $http_factory, $http_factory, self::OAUTH2_CONFIG_EXAMPLE);

        $server_request = $http_factory->createServerRequest('GET', 'http://example.com/userinfo');
        $server_request = $server_request->withHeader('Authorization', 'Bearer foo');

        $middleware->process($server_request, $handler_stub);
    }

    public function testExceptionThrownWhenNoAccessTokenPresent()
    {
        $this->expectException(Oauth2IntrospectionException::class);
        $this->expectExceptionCode(Oauth2IntrospectionException::ACCESS_TOKEN_EMPTY);

        $http_factory     = new HttpFactory();
        $http_client_stub = $this->createStub(ClientInterface::class);
        $handler_stub     = $this->createStub(RequestHandlerInterface::class);
        $middleware       = new Oauth2Introspection($http_client_stub, $http_factory, $http_factory, self::OAUTH2_CONFIG_EXAMPLE);

        $server_request = $http_factory->createServerRequest('GET', 'http://example.com/userinfo');
        $server_request = $server_request->withHeader('Authorization', 'Bearer');

        $middleware->process($server_request, $handler_stub);
    }

    public function testExceptionThrownWhenAccessTokenInactive()
    {
        $this->expectException(Oauth2IntrospectionException::class);
        $this->expectExceptionCode(Oauth2IntrospectionException::ACCESS_TOKEN_INACTIVE);

        $http_factory = new HttpFactory();

        $http_client_stub       = $this->createStub(ClientInterface::class);
        $introspection_response = $http_factory->createResponse(200);
        $introspection_response = $introspection_response->withHeader('Content-Type', 'application/json');
        $introspection_response = $introspection_response->withBody($http_factory->createStream(json_encode(['active' => false])));
        $http_client_stub->method('sendRequest')->willReturn($introspection_response);

        $handler_stub = $this->createStub(RequestHandlerInterface::class);

        $server_request = $http_factory->createServerRequest('GET', 'http://example.com/userinfo');
        $server_request = $server_request->withHeader('Authorization', 'Bearer '.self::JWT_TEST);

        $middleware = new Oauth2Introspection($http_client_stub, $http_factory, $http_factory, self::OAUTH2_CONFIG_EXAMPLE);

        $middleware->process($server_request, $handler_stub);
    }

    public function testExceptionThrownWhenAuthorizationServerError()
    {
        $this->expectException(Oauth2IntrospectionException::class);
        $this->expectExceptionCode(Oauth2IntrospectionException::AUTHORIZATION_SERVER_ERROR);

        $http_factory = new HttpFactory();

        $http_client_stub = $this->createStub(ClientInterface::class);
        $http_client_stub->method('sendRequest')->willReturn($http_factory->createResponse(500));

        $handler_stub = $this->createStub(RequestHandlerInterface::class);

        $server_request = $http_factory->createServerRequest('GET', 'http://example.com/userinfo');
        $server_request = $server_request->withHeader('Authorization', 'Bearer '.self::JWT_TEST);

        $middleware = new Oauth2Introspection($http_client_stub, $http_factory, $http_factory, self::OAUTH2_CONFIG_EXAMPLE);

        $middleware->process($server_request, $handler_stub);
    }

    public function testIntrospectionRequest()
    {
        $http_factory = new HttpFactory();

        $introspection_response = $http_factory->createResponse(200);
        $introspection_response = $introspection_response->withHeader('Content-Type', 'application/json');
        $introspection_response = $introspection_response->withBody($http_factory->createStream(json_encode(['active' => true, 'foo' => 'bar'])));

        $http_client_stub = $this->createStub(ClientInterface::class);
        $http_client_stub->method('sendRequest')->willReturn($introspection_response);

        $server_request = $http_factory->createServerRequest('GET', 'http://example.com/userinfo');
        $server_request = $server_request->withHeader('Authorization', 'Bearer '.self::JWT_TEST);

        $handler_stub                           = $this->createStub(RequestHandlerInterface::class);
        $server_request_with_introspection_data = $server_request->withAttribute(Oauth2Introspection::INTROSPECTION_DATA_ATTRIBUTE_NAME, ['active' => true, 'foo' => 'bar']);
        $handler_stub->method('handle')->with($server_request_with_introspection_data)->willReturn(new Response());

        $middleware = new Oauth2Introspection($http_client_stub, $http_factory, $http_factory, self::OAUTH2_CONFIG_EXAMPLE);

        $response = $middleware->process($server_request, $handler_stub);

        $this->assertInstanceOf(ResponseInterface::class, $response);
    }

    public function testIntrospectionRequestWithCache()
    {
        $access_token = self::JWT_TEST;
        $expires_at   = '1687594342'; // Expires at 24/6/2023

        $http_factory = new HttpFactory();

        $introspection_response = $http_factory->createResponse(200);
        $introspection_response = $introspection_response->withHeader('Content-Type', 'application/json');
        $introspection_response = $introspection_response->withBody($http_factory->createStream(json_encode(['active' => true, 'exp' => $expires_at])));

        $http_client_stub = $this->createStub(ClientInterface::class);
        $http_client_stub->method('sendRequest')->willReturn($introspection_response);

        $server_request = $http_factory->createServerRequest('GET', 'http://example.com/userinfo');
        $server_request = $server_request->withHeader('Authorization', "Bearer $access_token");

        $handler_stub = $this->createStub(RequestHandlerInterface::class);
        $handler_stub->method('handle')->willReturn(new Response());

        $middleware = new Oauth2Introspection($http_client_stub, $http_factory, $http_factory, self::OAUTH2_CONFIG_EXAMPLE);

        $cache = new Psr6CacheTest();
        $middleware->enableCache($cache);

        $this->assertFalse($cache->getItem(sprintf(Oauth2Introspection::CACHE_KEY_FORMAT, $access_token))->isHit());

        $response = $middleware->process($server_request, $handler_stub);
        $this->assertInstanceOf(ResponseInterface::class, $response);

        $this->assertTrue($cache->getItem(sprintf(Oauth2Introspection::CACHE_KEY_FORMAT, $access_token))->isHit());
    }
}
