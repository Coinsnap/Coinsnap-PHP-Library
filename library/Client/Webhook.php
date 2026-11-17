<?php
declare(strict_types=1);
namespace Coinsnap\Client;

class Webhook extends AbstractClient {
    
    public function getWebhook(string $storeId, string $webhookId): \Coinsnap\Result\Webhook {
        $url = $this->getApiUrl() . '' . COINSNAP_SERVER_PATH . '/' . urlencode($storeId) . '/webhooks/' . urlencode($webhookId);
        $headers = $this->getRequestHeaders();
        $method = 'GET';
        $response = $this->getHttpClient()->request($method, $url, $headers);

        if ($response->getStatus() === 200) {
            $data = json_decode($response->getBody(), true, 512, JSON_THROW_ON_ERROR);
            return new \Coinsnap\Result\Webhook($data);
        } else {
            throw $this->getExceptionByStatusCode($method, $url, (int)$response->getStatus(), $response->getBody());
        }
    }
    
    /**
     * Like getWebhook(), but keeps "not found" apart from an API error.
     *
     * @return \Coinsnap\Result\Webhook|null null if the webhook does not exist (400 or 404).
     * @throws \Coinsnap\Exception\CSException on a network error or any other API answer:
     *         never treat that as "no webhook", or a glitch creates a new webhook and replaces the secret.
     */
    public function findWebhook(string $storeId, string $webhookId): ?\Coinsnap\Result\Webhook {
        $url = $this->getApiUrl() . '' . COINSNAP_SERVER_PATH . '/' . urlencode($storeId) . '/webhooks/' . urlencode($webhookId);
        $method = 'GET';
        $response = $this->getHttpClient()->request($method, $url, $this->getRequestHeaders());
        $status = (int) $response->getStatus();

        if ($status === 400 || $status === 404) {
            return null;
        }
        if ($status !== 200) {
            throw $this->getExceptionByStatusCode($method, $url, $status, $response->getBody());
        }
        $data = json_decode($response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($data)) {
            throw $this->getExceptionByStatusCode($method, $url, $status, '');
        }
        return new \Coinsnap\Result\Webhook($data);
    }

    public function createWebhook(string $storeId, string $url, ?array $specificEvents, ?string $secret): \Coinsnap\Result\WebhookCreated {
        $data = ['url' => $url];

        if (isset($specificEvents) && count($specificEvents) > 0) {
            $data['events'] = $specificEvents;
        }
        elseif (count($specificEvents) === 0) {
            throw new \InvalidArgumentException('Argument $specificEvents should be NULL or contains at least 1 item.');
        } 
        else {
            $data['authorizedEvents'] = ['everything' => false,'specificEvents' => $specificEvents];
        }

        if ($secret === '') {
            throw new \InvalidArgumentException('Argument $secret should be NULL (let Server auto-generate a secret) or you should provide a long and safe secret string.');
        } elseif ($secret !== null) {
            $data['secret'] = $secret;
        }
        
        $url = $this->getApiUrl() . '' . COINSNAP_SERVER_PATH . '/' . urlencode($storeId) . '/webhooks';
        $headers = $this->getRequestHeaders();

        $method = 'POST';
        $response = $this->getHttpClient()->request($method, $url, $headers, json_encode($data, JSON_THROW_ON_ERROR));
        
        if ($response->getStatus() === 200) {
            $data = json_decode($response->getBody(), true, 512, JSON_THROW_ON_ERROR);
            $result = new \Coinsnap\Result\WebhookCreated($data);
            return $result;
        } else {
            throw $this->getExceptionByStatusCode($method, $url, (int)$response->getStatus(), $response->getBody());
        }
    }

    /**
     * Updates an existing webhook.
     *
     * @return \Coinsnap\Result\Webhook
     * @throws \JsonException
     */
    public function updateWebhook(string $storeId, string $url, string $webhookId, ?array $specificEvents, bool $enabled = true, ?string $secret = null): \Coinsnap\Result\Webhook
    {
        $data = [
            'enabled' => $enabled,
            'url' => $url,
            'secret' => $secret
        ];

        if (isset($specificEvents) && count($specificEvents) > 0) {
            $data['events'] = $specificEvents;
        }

        $url = $this->getApiUrl() . '' . COINSNAP_SERVER_PATH . '/' . urlencode($storeId) . '/webhooks/' . urlencode($webhookId);
        $headers = $this->getRequestHeaders();
        $method = 'PUT';
        $response = $this->getHttpClient()->request($method, $url, $headers, json_encode($data, JSON_THROW_ON_ERROR));

        if ($response->getStatus() === 200) {
            $data = json_decode($response->getBody(), true, 512, JSON_THROW_ON_ERROR);
            return new \Coinsnap\Result\Webhook($data);
        } else {
            throw $this->getExceptionByStatusCode($method, $url, (int)$response->getStatus(), $response->getBody());
        }
    }

    public const SIGNATURE_OK = 'ok';
    public const SIGNATURE_BAD = 'bad signature';
    public const SIGNATURE_STALE = 'stale timestamp';

    /** Oldest (and newest) accepted X-Coinsnap-Signature timestamp, in seconds from now. */
    public const SIGNATURE_TOLERANCE = 300;

    /**
     * Checks the old, untimestamped signature ("sha256=<hex>" over the body): the X-Coinsnap-Sig
     * header, or BTCPay's BTCPay-Sig header. Timing-safe; an empty secret rejects every request.
     *
     * @deprecated for Coinsnap: X-Coinsnap-Sig has no time in it, so a captured webhook can be
     *             replayed forever. Use isIncomingWebhookSignatureValid() with X-Coinsnap-Signature.
     *             For BTCPay use isIncomingBTCPayWebhookRequestValid() (same check, clearer name).
     */
    public static function isIncomingWebhookRequestValid(string $requestBody, string $coinsnapSignatureHeader, string $secret): bool
    {
        return self::isIncomingBTCPayWebhookRequestValid($requestBody, $coinsnapSignatureHeader, $secret);
    }

    /**
     * BTCPay-Sig: sha256=<hex>, HMAC-SHA256 of the raw body. Compared including the prefix,
     * timing-safe. An empty secret, header or body rejects.
     */
    public static function isIncomingBTCPayWebhookRequestValid(string $requestBody, string $btcpaySigHeader, string $secret): bool
    {
        if ($secret === '' || $requestBody === '' || $btcpaySigHeader === '') {
            return false;
        }
        $expectedHeader = 'sha256=' . hash_hmac('sha256', $requestBody, $secret);
        return hash_equals($expectedHeader, trim($btcpaySigHeader));
    }

    /**
     * X-Coinsnap-Signature: t=<unix time>,v1=<hex>, where v1 = HMAC-SHA256 of "t.body".
     * Use the result as the log reason when it is not SIGNATURE_OK.
     *
     * @param string   $requestBody     The raw request body, exactly as received.
     * @param string   $signatureHeader The X-Coinsnap-Signature header.
     * @param string   $secret          This plugin's webhook secret for this store. '' rejects.
     * @param int|null $now             Current unix time (for tests); defaults to time().
     * @return string SIGNATURE_OK, SIGNATURE_BAD or SIGNATURE_STALE
     */
    public static function checkIncomingWebhookSignature(string $requestBody, string $signatureHeader, string $secret, ?int $now = null, int $tolerance = self::SIGNATURE_TOLERANCE): string
    {
        if ($secret === '' || $signatureHeader === '') {
            return self::SIGNATURE_BAD;
        }
        $t = '';
        $signatures = [];
        foreach (explode(',', $signatureHeader) as $part) {
            $kv = explode('=', trim($part), 2);
            if (count($kv) !== 2) {
                continue;
            }
            if ($kv[0] === 't') {
                $t = $kv[1];
            } elseif ($kv[0] === 'v1' && $kv[1] !== '') {
                $signatures[] = strtolower($kv[1]);
            }
        }
        if (!preg_match('/^[1-9][0-9]{0,11}$/', $t) || $signatures === []) {
            return self::SIGNATURE_BAD;
        }
        $expected = hash_hmac('sha256', $t . '.' . $requestBody, $secret);
        $valid = false;
        foreach ($signatures as $signature) {
            if (hash_equals($expected, $signature)) {
                $valid = true;
            }
        }
        if (!$valid) {
            return self::SIGNATURE_BAD;
        }
        if (abs(($now ?? time()) - (int) $t) > $tolerance) {
            return self::SIGNATURE_STALE;
        }
        return self::SIGNATURE_OK;
    }

    /** True only if checkIncomingWebhookSignature() returns SIGNATURE_OK. */
    public static function isIncomingWebhookSignatureValid(string $requestBody, string $signatureHeader, string $secret, ?int $now = null, int $tolerance = self::SIGNATURE_TOLERANCE): bool
    {
        return self::checkIncomingWebhookSignature($requestBody, $signatureHeader, $secret, $now, $tolerance) === self::SIGNATURE_OK;
    }

    public function deleteWebhook(string $storeId, string $webhookId): void
    {
        $url = $this->getApiUrl() . '' . COINSNAP_SERVER_PATH . '/' . urlencode($storeId) . '/webhooks/' . urlencode($webhookId);
        $headers = $this->getRequestHeaders();
        $method = 'DELETE';
        $response = $this->getHttpClient()->request($method, $url, $headers);

        if ($response->getStatus() !== 204 && $response->getStatus() !== 200) {
            throw $this->getExceptionByStatusCode($method, $url, (int)$response->getStatus(), $response->getBody());
        }
    }

    /**
     * Get all webhooks for a specific store
     * @param string $storeId
     * @return \Coinsnap\Result\Webhook[]
     */
    public function getWebhooks(string $storeId): array
    {
        $url = $this->getApiUrl() . '' . COINSNAP_SERVER_PATH . '/' . urlencode($storeId) . '/webhooks';
        $headers = $this->getRequestHeaders();
        $method = 'GET';
        $response = $this->getHttpClient()->request($method, $url, $headers);

        if ($response->getStatus() === 200) {
            $r = [];
            $data = json_decode($response->getBody(), true, 512, JSON_THROW_ON_ERROR);
            foreach ($data as $item) {
                $item = new \Coinsnap\Result\Webhook($item);
                $r[] = $item;
            }
            return $r;
        } else {
            throw $this->getExceptionByStatusCode($method, $url, (int)$response->getStatus(), $response->getBody());
        }
    }
}
