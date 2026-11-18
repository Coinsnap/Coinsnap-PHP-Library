<?php
declare(strict_types=1);
namespace Coinsnap\Exception;

/**
 * An API answer other than the expected one.
 *
 * The message names the method, the API path with its IDs masked (/stores/{id}/invoices/{id})
 * and the status, so it can be logged without the store ID (guide rule 6.13). The raw answer
 * is not in the message, since it can echo request data; read it with getResponseBody() if needed,
 * and don't show or log it.
 */
class RequestException extends CSException {
    /** @var string */
    private $method;
    /** @var int */
    private $status;
    /** @var string */
    private $responseBody;

    public function __construct(string $method, string $url, int $status, string $body){
        $this->method = $method;
        $this->status = $status;
        $this->responseBody = $body;
        $message = 'Error during ' . $method . ' to ' . self::maskUrl($url) . '. Got response (' . $status . ').';
        parent::__construct($message, $status);
    }

    public function getMethod(): string {
        return $this->method;
    }

    public function getStatus(): int {
        return $this->status;
    }

    public function getResponseBody(): string {
        return $this->responseBody;
    }

    /** Drops the query string and replaces every path segment after a collection name with {id}. */
    public static function maskUrl(string $url): string {
        $path = (string) parse_url($url, PHP_URL_PATH);
        $host = (string) parse_url($url, PHP_URL_HOST);
        $masked = preg_replace(
            '#/(stores|invoices|webhooks|users|api-keys|payment-methods|payments|pull-payments|payouts)/(?!current\b)[^/]+#i',
            '/$1/{id}',
            $path
        );
        return ($host !== '' ? $host : '') . $masked;
    }
}
