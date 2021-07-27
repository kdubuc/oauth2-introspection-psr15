<?php

namespace Kdubuc\Middleware;

use Psr\Http\Client\ClientInterface;
use Psr\Cache\CacheItemPoolInterface;
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
    public const CACHE_KEY_FORMAT                  = 'at_%s';
    public const JWT_REGEX                         = '/^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.(?:[a-zA-Z0-9\-_]+)?$/';

    private ClientInterface $http_client;
    private StreamFactoryInterface $http_stream_factory;
    private RequestFactoryInterface $http_request_factory;
    private ?CacheItemPoolInterface $cache_pool = null;
    private array $oauth2_config;
    private ?string $token_type_hint = null;

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

        // Retrieve an array of all the Authorization header values
        $authorization_headers = $server_request->getHeader('Authorization');
        if (!\is_array($authorization_headers) || 0 === \count($authorization_headers)) {
            throw new Oauth2IntrospectionException('No Authorization header provided', Oauth2IntrospectionException::AUTHORIZATION_HEADER_NOT_FOUND);
        }

        // Get access_token in the server request's Authorization header.
        $access_token = trim(preg_replace('/^(?:\s+)?Bearer\s?/', '', array_shift($authorization_headers)));
        if (empty($access_token)) {
            throw new Oauth2IntrospectionException('No access token found', Oauth2IntrospectionException::ACCESS_TOKEN_EMPTY);
        }

        // If access token is malformed, throw an Exception
        preg_match(self::JWT_REGEX, $access_token, $matches);
        if (empty($matches) || $matches[0] !== $access_token) {
            throw new Oauth2IntrospectionException('Access token is malformed', Oauth2IntrospectionException::ACCESS_TOKEN_INVALID);
        }

        // Request the access_token introspection data in cache (if enabled, otherwise, cache_item will be null)
        $cache_key  = sprintf(self::CACHE_KEY_FORMAT, $access_token);
        $cache_item = null !== $this->cache_pool ? $this->cache_pool->getItem($cache_key) : null;

        // If the cache is not enabled, or access_token is not found in cache, we must talk with the introspection endpoint
        if (null === $cache_item || !$cache_item->isHit()) {
            // Set up introspection request parameters.
            $introspection_parameters = ['token' => $access_token];

            // If token type hint is defined, add it to the parameters
            if (null !== $this->token_type_hint) {
                $introspection_parameters['token_type_hint'] = $this->token_type_hint;
            }

            // Build HTTP introspection request.
            $introspection_request = $this->http_request_factory->createRequest('POST', $introspection_endpoint);
            $introspection_request = $introspection_request->withHeader('Content-Type', 'application/x-www-form-urlencoded');
            $introspection_request = $introspection_request->withHeader('Authorization', 'Basic '.base64_encode("$oauth2_client_id:$oauth2_client_secret"));
            $introspection_request = $introspection_request->withBody($this->http_stream_factory->createStream(http_build_query($introspection_parameters, '', '&')));

            // Talk to introspection endpoint
            $introspection_response = $this->http_client->sendRequest($introspection_request);

            // If status code is not 200 - OK, throw an exception
            if (200 !== $introspection_response->getStatusCode()) {
                throw new Oauth2IntrospectionException('Authorization server encountered an error', Oauth2IntrospectionException::AUTHORIZATION_SERVER_ERROR);
            }

            // Parse the introspection results
            $introspection_data = json_decode(trim((string) $introspection_response->getBody()), true, 512, \JSON_THROW_ON_ERROR);

            // Save introspection results into the cache pool (if enabled, and expiration timestamp of the token exists in introspection data)
            if (null !== $this->cache_pool && \array_key_exists('exp', $introspection_data)) {
                $cache_item->set(json_encode($introspection_data, \JSON_THROW_ON_ERROR));
                $cache_item->expiresAfter((int) $introspection_data['exp'] - time());
                $this->cache_pool->save($cache_item);
            }
        } else {
            $introspection_data = json_decode($cache_item->get(), true, 512, \JSON_THROW_ON_ERROR);
        }

        // The specifics of a token's "active" state will vary depending on the implementation of the authorization
        // server and the information it keeps about its tokens, but a "true" value return for the "active" property
        // will generally indicate that a given token has been issued by this authorization server, has not been revoked
        // by the resource owner, and is within its given time window of validity (https://tools.ietf.org/html/rfc7662#section-2.2)
        if (true !== $introspection_data['active']) {
            throw new Oauth2IntrospectionException('The resource owner or authorization server denied the request', Oauth2IntrospectionException::ACCESS_TOKEN_INACTIVE);
        }

        // Store introspection results data
        $server_request = $server_request->withAttribute(self::INTROSPECTION_DATA_ATTRIBUTE_NAME, $introspection_data);

        // Continue to process server request
        return $handler->handle($server_request);
    }

    /**
     * Enable cache pool to store introspection data.
     */
    public function enableCache(CacheItemPoolInterface $pool) : void
    {
        $this->cache_pool = $pool;
    }

    /**
     * A hint about the type of the token submitted for introspection to help the authorization server optimize the token lookup.
     */
    public function setTokenHint(string $token_type_hint) : void
    {
        // Values for this property are defined in the "OAuth Token Type Hints" registry defined in OAuth Token Revocation (https://tools.ietf.org/html/rfc7009#section-2.1)
        if (!\in_array($token_type_hint, ['access_token', 'refresh_token'])) {
            throw new Oauth2IntrospectionException("Token type hint $token_type_hint not defined in RFC7009 OAuth Token Revocation", Oauth2IntrospectionException::TOKEN_TYPE_HINT_UNKNOWN);
        }

        $this->token_type_hint = $token_type_hint;
    }
}
