<?php
declare(strict_types=1);
namespace Coinsnap\Http;
use Coinsnap\Exception\ConnectException;

/**
 * HTTP Client using cURL to communicate.
 */
class CurlClient implements ClientInterface
{
    protected $curlOptions = [];

    /**
     * Inits curl session adding any additional curl options set.
     * @return false|resource
     */
    protected function initCurl(){
        // We cannot set a return type here as it is "resource" for PHP < 8 and CurlHandle for PHP >= 8.
        $ch = curl_init();
        if ($ch) {
            curl_setopt_array($ch, [
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_TIMEOUT => 30,
            ]);
            if (count($this->curlOptions)) {
                curl_setopt_array($ch, $this->curlOptions);
            }
            // Always verify the server's TLS certificate, whatever setCurlOptions() was given:
            // without it anyone between the site and the API can answer with a fake "paid" invoice.
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        }
        return $ch;
    }

    /**
     * Set extra cURL options, e.g. a proxy, a timeout or a custom CA bundle (CURLOPT_CAINFO).
     * CURLOPT_SSL_VERIFYPEER and CURLOPT_SSL_VERIFYHOST cannot be turned off: they are ignored.
     * @return void
     */
    public function setCurlOptions(array $options){
        unset($options[CURLOPT_SSL_VERIFYPEER], $options[CURLOPT_SSL_VERIFYHOST]);
        $this->curlOptions = $options;
    }

    /**
     * @inheritdoc
     */
    public function request(string $method, string $url, array  $headers = [], string $body = ''): ResponseInterface {
        
        $flatHeaders = [];
        foreach ($headers as $key => $value) {
            $flatHeaders[] = $key . ': ' . $value;
        }

        $ch = $this->initCurl();
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HEADER, 1);
        if ($body !== '') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $flatHeaders);

        $response = curl_exec($ch);

        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);

        $responseHeaders = [];
        $responseBody = '';

        if ($response) {
            $responseString = is_string($response) ? $response : '';
            if ($responseString && $headerSize) {
                $responseBody = substr($responseString, $headerSize);
                $headerPart = substr($responseString, 0, $headerSize);
                $headerParts = explode("\n", $headerPart);
                foreach ($headerParts as $headerLine) {
                    $headerLine = trim($headerLine);
                    if ($headerLine) {
                        $parts = explode(':', $headerLine);
                        if (count($parts) === 2) {
                            $key = $parts[0];
                            $value = $parts[1];
                            $responseHeaders[$key] = $value;
                        }
                    }
                }
            }
        }
        else {
            $errorMessage = curl_error($ch);
            $errorCode = curl_errno($ch);
            throw new ConnectException($errorMessage, $errorCode);
        }

        return new Response($status, $responseBody, $responseHeaders);
    }
}
