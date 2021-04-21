<?php

use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\HttpFactory;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\ResponseInterface;
use Kdubuc\Middleware\Oauth2Introspection;
use Psr\Http\Server\RequestHandlerInterface;
use Kdubuc\Middleware\Oauth2IntrospectionException;

class Oauth2IntrospectionTest extends TestCase
{
    public const OAUTH2_CONFIG_EXAMPLE = [
        'introspection_endpoint' => 'http://oauth2.example.com/introspect',
        'oauth2_client_id'       => 'client_id',
        'oauth2_client_secret'   => 'client_secret',
    ];

    public function testExceptionThrownWhenNoAuthorizationHeader()
    {
        $this->expectException(Oauth2IntrospectionException::class);

        $http_factory     = new HttpFactory();
        $http_client_stub = $this->createStub(ClientInterface::class);
        $handler_stub     = $this->createStub(RequestHandlerInterface::class);
        $middleware       = new Oauth2Introspection($http_client_stub, $http_factory, $http_factory, self::OAUTH2_CONFIG_EXAMPLE);

        $server_request = $http_factory->createServerRequest('GET', 'http://example.com/userinfo');

        $middleware->process($server_request, $handler_stub);
    }

    public function testExceptionThrownWhenNoAccessTokenPresent()
    {
        $this->expectException(Oauth2IntrospectionException::class);

        $http_factory     = new HttpFactory();
        $http_client_stub = $this->createStub(ClientInterface::class);
        $handler_stub     = $this->createStub(RequestHandlerInterface::class);
        $middleware       = new Oauth2Introspection($http_client_stub, $http_factory, $http_factory, self::OAUTH2_CONFIG_EXAMPLE);

        $server_request = $http_factory->createServerRequest('GET', 'http://example.com/userinfo');
        $server_request = $server_request->withHeader('Authorization', 'Bearer');

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
        $server_request = $server_request->withHeader('Authorization', 'Bearer xxxx');

        $handler_stub                           = $this->createStub(RequestHandlerInterface::class);
        $server_request_with_introspection_data = $server_request->withAttribute(Oauth2Introspection::INTROSPECTION_DATA_ATTRIBUTE_NAME, ['active' => true, 'foo' => 'bar']);
        $handler_stub->method('handle')->with($server_request_with_introspection_data)->willReturn(new Response());

        $middleware = new Oauth2Introspection($http_client_stub, $http_factory, $http_factory, self::OAUTH2_CONFIG_EXAMPLE);

        $response = $middleware->process($server_request, $handler_stub);

        $this->assertInstanceOf(ResponseInterface::class, $response);
    }
}
