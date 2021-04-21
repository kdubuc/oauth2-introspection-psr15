<?php

namespace Kdubuc\Middleware;

use Exception;
use Assert\Assert;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\RequestFactoryInterface;

/*
 * OAuth2 Introspection Middleware (https://tools.ietf.org/html/rfc7662).
 * Store the introspection results data in server_request attributes.
 */
final class Oauth2Introspection implements MiddlewareInterface
{
    public const INTROSPECTION_DATA_ATTRIBUTE_NAME = 'oauth2_access_token_introspection_data';

    /**
     * Configure OAuth2 Introspection endpoint.
     */
    public function __construct(
        ClientInterface $http_client,
        StreamFactoryInterface $http_stream_factory,
        RequestFactoryInterface $http_request_factory,
        array $oauth2_config
    ) {
        $this->oauth2_config        = $oauth2_config;
        $this->http_client          = $http_client;
        $this->http_request_factory = $http_request_factory;
        $this->http_stream_factory  = $http_stream_factory;
    }

    /**
     * Process an incoming server request.
     */
    public function process(ServerRequestInterface $server_request, RequestHandlerInterface $handler) : ResponseInterface
    {
        // Export OAuth2 config
        $introspection_endpoint = $this->oauth2_config['introspection_endpoint'];
        $oauth2_client_id       = $this->oauth2_config['oauth2_client_id'];
        $oauth2_client_secret   = $this->oauth2_config['oauth2_client_secret'];

        // Get access_token in the server request's Authorization header.
        Assert::that($authorization_headers = $server_request->getHeader('Authorization'), 'No Authorization header provided')->isArray()->notEmpty();
        $access_token = trim(preg_replace('/^(?:\s+)?Bearer\s?/', '', array_shift($authorization_headers)));
        Assert::that($access_token, 'No access token found')->notEmpty()->string();

        // Build HTTP introspection request.
        $introspection_request = $this->http_request_factory->createRequest('POST', $introspection_endpoint);
        $introspection_request = $introspection_request->withHeader('Content-Type', 'application/x-www-form-urlencoded');
        $introspection_request = $introspection_request->withHeader('Authorization', 'Basic '.base64_encode("$oauth2_client_id:$oauth2_client_secret"));
        $introspection_request = $introspection_request->withBody($this->http_stream_factory->createStream(http_build_query(['token' => $access_token, 'token_type_hint' => 'access_token'], '', '&')));

        // Talk to introspection endpoint
        $introspection_response = $this->http_client->sendRequest($introspection_request);

        // Parse the introspection results
        $introspection_data = json_decode(trim((string) $introspection_response->getBody()), true, 512, \JSON_THROW_ON_ERROR);

        // The specifics of a token's "active" state will vary depending on the implementation of the authorization
        // server and the information it keeps about its tokens, but a "true" value return for the "active" property
        // will generally indicate that a given token has been issued by this authorization server, has not been revoked
        // by the resource owner, and is within its given time window of validity (https://tools.ietf.org/html/rfc7662#section-2.2)
        if (true !== $introspection_data['active']) {
            throw new Exception('The resource owner or authorization server denied the request.');
        }

        // Store introspection results data
        $server_request = $server_request->withAttribute(self::INTROSPECTION_DATA_ATTRIBUTE_NAME, $introspection_data);

        // Continue to process server request
        return $handler->handle($server_request);
    }
}
