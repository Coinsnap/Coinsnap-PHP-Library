<?php
/**
 * Unit tests for the security-relevant parts of the library. No dependencies:
 *   php tests/security-test.php
 * Exits 1 if any test fails. Runs against library/ (loader.php); src/ is the same code.
 */
declare(strict_types=1);

require __DIR__ . '/../library/loader.php';

use Coinsnap\Client\APIWebhook;
use Coinsnap\Client\BTCPayApiAuthorization;
use Coinsnap\Client\Invoice;
use Coinsnap\Client\Webhook;
use Coinsnap\Exception\ConnectException;
use Coinsnap\Exception\CSException;
use Coinsnap\Exception\RequestException;
use Coinsnap\Http\ClientInterface;
use Coinsnap\Http\CurlClient;
use Coinsnap\Http\Response;
use Coinsnap\Http\ResponseInterface;

class FakeHttp implements ClientInterface {
    public $requests = [];
    private $answer;
    public function __construct($answer) { $this->answer = $answer; }
    public function request(string $method, string $url, array $headers = [], string $body = ''): ResponseInterface {
        $this->requests[] = compact('method', 'url', 'headers', 'body');
        if ($this->answer instanceof \Throwable) {
            throw $this->answer;
        }
        return $this->answer;
    }
}

$passed = 0;
$failed = 0;
function check(string $name, bool $ok): void {
    global $passed, $failed;
    if ($ok) { $passed++; } else { $failed++; echo "FAIL: $name\n"; }
}
function throws(callable $fn, string $class = \Throwable::class): bool {
    try { $fn(); } catch (\Throwable $e) { return $e instanceof $class; }
    return false;
}

$secret = 'test-secret-0123456789abcdef';
$body = '{"type":"Settled","invoiceId":"inv_1"}';
$now = 1_800_000_000;
$sign = function (int $t, ?string $b = null, ?string $s = null) use ($body, $secret): string {
    return 't=' . $t . ',v1=' . hash_hmac('sha256', $t . '.' . ($b ?? $body), $s ?? $secret);
};

/* ---------- X-Coinsnap-Signature ---------- */
check('valid signature', Webhook::checkIncomingWebhookSignature($body, $sign($now), $secret, $now) === Webhook::SIGNATURE_OK);
check('valid, 299s old', Webhook::isIncomingWebhookSignatureValid($body, $sign($now - 299), $secret, $now));
check('valid, spaces after comma', Webhook::isIncomingWebhookSignatureValid($body, str_replace(',', ', ', $sign($now)), $secret, $now));
check('valid, uppercase hex', Webhook::isIncomingWebhookSignatureValid($body, 't=' . $now . ',v1=' . strtoupper(hash_hmac('sha256', $now . '.' . $body, $secret)), $secret, $now));
check('valid, second v1 matches', Webhook::isIncomingWebhookSignatureValid($body, $sign($now) . ',v1=deadbeef', $secret, $now));
check('stale: 301s old', Webhook::checkIncomingWebhookSignature($body, $sign($now - 301), $secret, $now) === Webhook::SIGNATURE_STALE);
check('stale: 10 min old', Webhook::checkIncomingWebhookSignature($body, $sign($now - 600), $secret, $now) === Webhook::SIGNATURE_STALE);
check('stale: 10 min in future', Webhook::checkIncomingWebhookSignature($body, $sign($now + 600), $secret, $now) === Webhook::SIGNATURE_STALE);
check('stale uses real time by default', Webhook::checkIncomingWebhookSignature($body, $sign(time() - 600), $secret) === Webhook::SIGNATURE_STALE);
check('fresh uses real time by default', Webhook::isIncomingWebhookSignatureValid($body, $sign(time()), $secret));
check('missing header', Webhook::checkIncomingWebhookSignature($body, '', $secret, $now) === Webhook::SIGNATURE_BAD);
check('wrong secret', Webhook::checkIncomingWebhookSignature($body, $sign($now, null, 'other'), $secret, $now) === Webhook::SIGNATURE_BAD);
check('body changed', Webhook::checkIncomingWebhookSignature($body . ' ', $sign($now), $secret, $now) === Webhook::SIGNATURE_BAD);
check('t changed', Webhook::checkIncomingWebhookSignature($body, str_replace('t=' . $now, 't=' . ($now - 1), $sign($now)), $secret, $now) === Webhook::SIGNATURE_BAD);
check('no t', Webhook::checkIncomingWebhookSignature($body, 'v1=' . hash_hmac('sha256', '.' . $body, $secret), $secret, $now) === Webhook::SIGNATURE_BAD);
check('t=0', Webhook::checkIncomingWebhookSignature($body, 't=0,v1=' . hash_hmac('sha256', '0.' . $body, $secret), $secret, $now) === Webhook::SIGNATURE_BAD);
check('non-numeric t', Webhook::checkIncomingWebhookSignature($body, 't=abc,v1=' . hash_hmac('sha256', 'abc.' . $body, $secret), $secret, $now) === Webhook::SIGNATURE_BAD);
check('no v1', Webhook::checkIncomingWebhookSignature($body, 't=' . $now, $secret, $now) === Webhook::SIGNATURE_BAD);
check('old sha256= format refused', Webhook::checkIncomingWebhookSignature($body, 'sha256=' . hash_hmac('sha256', $body, $secret), $secret, $now) === Webhook::SIGNATURE_BAD);
check('empty secret rejects even if signed with empty key', Webhook::checkIncomingWebhookSignature($body, $sign($now, null, ''), '', $now) === Webhook::SIGNATURE_BAD);
check('stale + wrong sig reports bad signature', Webhook::checkIncomingWebhookSignature($body, $sign($now - 600, null, 'x'), $secret, $now) === Webhook::SIGNATURE_BAD);

/* ---------- BTCPay-Sig and the old method ---------- */
$btcSig = 'sha256=' . hash_hmac('sha256', $body, $secret);
check('btcpay valid', Webhook::isIncomingBTCPayWebhookRequestValid($body, $btcSig, $secret));
check('btcpay without prefix refused', !Webhook::isIncomingBTCPayWebhookRequestValid($body, hash_hmac('sha256', $body, $secret), $secret));
check('btcpay wrong secret', !Webhook::isIncomingBTCPayWebhookRequestValid($body, 'sha256=' . hash_hmac('sha256', $body, 'x'), $secret));
check('btcpay empty secret rejects', !Webhook::isIncomingBTCPayWebhookRequestValid($body, 'sha256=' . hash_hmac('sha256', $body, ''), ''));
check('btcpay empty header', !Webhook::isIncomingBTCPayWebhookRequestValid($body, '', $secret));
check('deprecated method still accepts valid', Webhook::isIncomingWebhookRequestValid($body, $btcSig, $secret));
check('deprecated method: empty secret rejects', !Webhook::isIncomingWebhookRequestValid($body, 'sha256=' . hash_hmac('sha256', $body, ''), ''));

/* ---------- Invoice::findInvoice: three outcomes ---------- */
$invoiceJson = json_encode(['id' => 'inv_1', 'status' => 'Settled', 'amount' => '1000', 'currency' => 'SATS']);
$inv = function ($answer) { return new Invoice('https://app.coinsnap.io', 'key_abcd', new FakeHttp($answer)); };
$found = $inv(new Response(200, $invoiceJson, []))->findInvoice('store_1', 'inv_1');
check('found returns invoice', $found instanceof \Coinsnap\Result\Invoice && $found->getData()['status'] === 'Settled');
check('400 -> null (Coinsnap unknown)', $inv(new Response(400, '{"error":"x"}', []))->findInvoice('store_1', 'test_123') === null);
check('404 -> null (BTCPay unknown)', $inv(new Response(404, '', []))->findInvoice('store_1', 'test_123') === null);
check('empty invoice id -> null, no request', (function () { $h = new FakeHttp(new Response(200, '{}', [])); $r = (new Invoice('https://x', 'k', $h))->findInvoice('s', ''); return $r === null && $h->requests === []; })());
check('500 throws', throws(function () use ($inv) { $inv(new Response(500, 'oops', []))->findInvoice('store_1', 'inv_1'); }, RequestException::class));
check('503 throws', throws(function () use ($inv) { $inv(new Response(503, '', []))->findInvoice('store_1', 'inv_1'); }, CSException::class));
check('401 throws (bad key is not "not found")', throws(function () use ($inv) { $inv(new Response(401, '', []))->findInvoice('store_1', 'inv_1'); }, CSException::class));
check('403 throws', throws(function () use ($inv) { $inv(new Response(403, '', []))->findInvoice('store_1', 'inv_1'); }, CSException::class));
check('network error throws', throws(function () use ($inv) { $inv(new ConnectException('Could not resolve host', 6))->findInvoice('store_1', 'inv_1'); }, ConnectException::class));
check('200 with junk throws', throws(function () use ($inv) { $inv(new Response(200, '<html>', []))->findInvoice('store_1', 'inv_1'); }, CSException::class));
check('getInvoice still throws on 400 (unchanged)', throws(function () use ($inv) { $inv(new Response(400, '', []))->getInvoice('store_1', 'inv_1'); }, CSException::class));
$h = new FakeHttp(new Response(200, $invoiceJson, []));
(new Invoice('https://app.coinsnap.io/', 'key_abcd', $h))->findInvoice('store/1', 'inv?1');
check('ids are url-encoded in path', strpos($h->requests[0]['url'], '/stores/store%2F1/invoices/inv%3F1') !== false);
check('x-api-key header sent', ($h->requests[0]['headers']['x-api-key'] ?? '') === 'key_abcd');

/* ---------- Exception messages: no store ID, no body ---------- */
try {
    $inv(new Response(500, '{"echo":"x-api-key: key_abcd"}', []))->findInvoice('store_SECRETID', 'inv_1');
    check('500 should throw', false);
} catch (RequestException $e) {
    check('message has no store ID', strpos($e->getMessage(), 'store_SECRETID') === false);
    check('message has no invoice ID', strpos($e->getMessage(), 'inv_1') === false);
    check('message has no response body', strpos($e->getMessage(), 'key_abcd') === false);
    check('message has masked path', strpos($e->getMessage(), '/stores/{id}/invoices/{id}') !== false);
    check('status kept', $e->getStatus() === 500 && $e->getCode() === 500);
    check('body available via getter', $e->getResponseBody() === '{"echo":"x-api-key: key_abcd"}');
}
check('maskUrl webhooks + query', RequestException::maskUrl('https://h/api/v1/stores/abc/webhooks/w1?x=secret') === 'h/api/v1/stores/{id}/webhooks/{id}');
check('maskUrl keeps api-keys/current', RequestException::maskUrl('https://h/api/v1/api-keys/current') === 'h/api/v1/api-keys/current');

/* ---------- Webhook::findWebhook / APIWebhook::checkWebhookExists ---------- */
$whJson = json_encode(['id' => 'wh_1', 'url' => 'https://shop.example/webhook', 'enabled' => true]);
$wh = function ($answer) { return new Webhook('https://app.coinsnap.io', 'k', new FakeHttp($answer)); };
check('findWebhook found', $wh(new Response(200, $whJson, []))->findWebhook('s', 'wh_1') instanceof \Coinsnap\Result\Webhook);
check('findWebhook 404 -> null', $wh(new Response(404, '', []))->findWebhook('s', 'wh_1') === null);
check('findWebhook 500 throws', throws(function () use ($wh) { $wh(new Response(500, '', []))->findWebhook('s', 'wh_1'); }, CSException::class));
$stored = ['id' => 'wh_1', 'url' => 'https://shop.example/webhook'];
check('checkWebhookExists true', APIWebhook::checkWebhookExists('https://app.coinsnap.io', 'k', 's', $stored, new FakeHttp(new Response(200, $whJson, []))) === true);
check('checkWebhookExists url changed -> false', APIWebhook::checkWebhookExists('https://app.coinsnap.io', 'k', 's', ['id' => 'wh_1', 'url' => 'https://other/webhook'], new FakeHttp(new Response(200, $whJson, []))) === false);
check('checkWebhookExists gone -> false', APIWebhook::checkWebhookExists('https://app.coinsnap.io', 'k', 's', $stored, new FakeHttp(new Response(404, '', []))) === false);
check('checkWebhookExists nothing stored -> false', APIWebhook::checkWebhookExists('https://app.coinsnap.io', 'k', 's', null, new FakeHttp(new Response(200, $whJson, []))) === false);
check('checkWebhookExists API error throws', throws(function () use ($stored) { APIWebhook::checkWebhookExists('https://app.coinsnap.io', 'k', 's', $stored, new FakeHttp(new Response(502, '', []))); }, CSException::class));
check('checkWebhookExists network error throws', throws(function () use ($stored) { APIWebhook::checkWebhookExists('https://app.coinsnap.io', 'k', 's', $stored, new FakeHttp(new ConnectException('timeout', 28))); }, ConnectException::class));

/* ---------- BTCPayApiAuthorization ---------- */
$store = 'Store123';
$good = [
    'btcpay.store.cancreateinvoice:' . $store,
    'btcpay.store.canviewinvoices:' . $store,
    'btcpay.store.webhooks.canmodifywebhooks:' . $store,
];
$auth = function (array $perms, ?string $key = 'apikey_1') { return new BTCPayApiAuthorization(['apiKey' => $key, 'permissions' => $perms]); };
check('acceptable minimal key', $auth($good)->isAcceptable());
check('acceptable with extra store permission', $auth(array_merge($good, ['btcpay.store.canviewstoresettings:' . $store]))->isAcceptable());
check('acceptable for named store', $auth($good)->isAcceptable(BTCPayApiAuthorization::MINIMUM_PERMISSIONS, $store));
check('refused for other store', !$auth($good)->isAcceptable(BTCPayApiAuthorization::MINIMUM_PERMISSIONS, 'OtherStore'));
check('refused: unrestricted', !$auth(array_merge($good, ['unrestricted']))->isAcceptable());
check('refused: unrestricted first', !$auth(array_merge(['unrestricted'], $good))->isAcceptable());
check('refused: server permission', !$auth(array_merge($good, ['btcpay.server.canmodifyserversettings']))->isAcceptable());
check('refused: user permission', !$auth(array_merge($good, ['btcpay.user.canviewprofile']))->isAcceptable());
check('refused: store perm for all stores', !$auth(array_merge($good, ['btcpay.store.canmodifystoresettings']))->isAcceptable());
check('refused: two stores', !$auth(array_merge($good, ['btcpay.store.canviewinvoices:Other']))->isAcceptable());
check('refused: missing webhook permission', !$auth(array_slice($good, 0, 2))->isAcceptable());
check('refused: no permissions', !$auth([])->isAcceptable());
check('refused: no api key', !$auth($good, null)->isAcceptable());
check('refused: empty api key', !$auth($good, '')->isAcceptable());
check('getStoreID', $auth($good)->getStoreID() === $store);
check('getStoreID empty perms -> ""', $auth([])->getStoreID() === '');
check('getStoreID unscoped -> ""', $auth(['unrestricted'])->getStoreID() === '');
check('hasSingleStore false for empty', !$auth([])->hasSingleStore());
check('hasSingleStore true', $auth($good)->hasSingleStore());
check('hasSingleStore false for two', !$auth(array_merge($good, ['btcpay.store.canviewinvoices:Other']))->hasSingleStore());
check('hasSingleStore false for empty store id', !$auth(['btcpay.store.canviewinvoices:'])->hasSingleStore());
$legacy = array_map(function ($p) use ($store) { return $p . ':' . $store; }, BTCPayApiAuthorization::REQUIRED_PERMISSIONS);
check('legacy hasRequiredPermissions unchanged (true)', $auth($legacy)->hasRequiredPermissions());
check('legacy hasRequiredPermissions with optional', $auth(array_merge($legacy, ['btcpay.store.webhooks.canmodifywebhooks:' . $store]))->hasRequiredPermissions());
check('legacy hasRequiredPermissions false for empty', !$auth([])->hasRequiredPermissions());
check('hasWebhookPermission', $auth($good)->hasWebhookPermission() && !$auth($legacy)->hasWebhookPermission());
check('constructor ignores junk input', (new BTCPayApiAuthorization('junk'))->getStoreID() === '' && (new BTCPayApiAuthorization(['permissions' => 'x']))->getPermissions() === []);
check('constructor drops non-string permissions', !throws(function () { (new BTCPayApiAuthorization(['permissions' => [['a'], 5, 'btcpay.store.canviewinvoices:S']]))->hasRequiredPermissions(); }));

// fromServer: asks BTCPay, ignores what was POSTed
$h = new FakeHttp(new Response(200, json_encode(['apiKey' => 'apikey_1', 'label' => 'x', 'permissions' => $good]), []));
$a = BTCPayApiAuthorization::fromServer('https://btcpay.example/', 'apikey_1', $h);
check('fromServer builds from server answer', $a !== null && $a->isAcceptable() && $a->getStoreID() === $store && $a->getApiKey() === 'apikey_1');
check('fromServer calls api-keys/current', $h->requests[0]['url'] === 'https://btcpay.example/api/v1/api-keys/current' && $h->requests[0]['method'] === 'GET');
check('fromServer sends token header', $h->requests[0]['headers']['Authorization'] === 'token apikey_1');
check('fromServer 401 -> null', BTCPayApiAuthorization::fromServer('https://btcpay.example', 'made-up', new FakeHttp(new Response(401, '', []))) === null);
check('fromServer junk -> null', BTCPayApiAuthorization::fromServer('https://btcpay.example', 'k', new FakeHttp(new Response(200, 'nope', []))) === null);
check('fromServer no permissions -> null', BTCPayApiAuthorization::fromServer('https://btcpay.example', 'k', new FakeHttp(new Response(200, '{"apiKey":"k"}', []))) === null);
check('fromServer other key in answer -> null', BTCPayApiAuthorization::fromServer('https://btcpay.example', 'k', new FakeHttp(new Response(200, json_encode(['apiKey' => 'other', 'permissions' => $good]), []))) === null);
check('fromServer unrestricted key is built but not acceptable', (function () { $a = BTCPayApiAuthorization::fromServer('https://b.example', 'k', new FakeHttp(new Response(200, json_encode(['apiKey' => 'k', 'permissions' => ['unrestricted']]), []))); return $a !== null && !$a->isAcceptable(); })());
check('fromServer empty key -> null, no request', (function () { $h = new FakeHttp(new Response(200, '{}', [])); return BTCPayApiAuthorization::fromServer('https://b.example', '', $h) === null && $h->requests === []; })());
check('fromServer empty url -> null', BTCPayApiAuthorization::fromServer('', 'k', new FakeHttp(new Response(200, '{}', []))) === null);
check('fromServer non-http url -> null', BTCPayApiAuthorization::fromServer('file:///etc', 'k', new FakeHttp(new Response(200, '{}', []))) === null);
check('fromServer network error throws', throws(function () { BTCPayApiAuthorization::fromServer('https://b.example', 'k', new FakeHttp(new ConnectException('down', 7))); }, ConnectException::class));

// one-time state
$state = BTCPayApiAuthorization::createState();
$hash = BTCPayApiAuthorization::hashState($state);
check('state is 64 hex', (bool) preg_match('/^[0-9a-f]{64}$/', $state));
check('states differ', BTCPayApiAuthorization::createState() !== $state);
check('state matches', BTCPayApiAuthorization::stateMatches($hash, $state));
check('wrong state', !BTCPayApiAuthorization::stateMatches($hash, BTCPayApiAuthorization::createState()));
check('empty state', !BTCPayApiAuthorization::stateMatches($hash, ''));
check('no stored state', !BTCPayApiAuthorization::stateMatches(null, $state));
check('empty stored state', !BTCPayApiAuthorization::stateMatches('', ''));
check('stored hash is not the state', !BTCPayApiAuthorization::stateMatches($state, $state));

/* ---------- CurlClient: TLS checks can't be turned off ---------- */
$c = new class extends CurlClient {
    public function options(): array { return $this->curlOptions; }
    public function handle() { return $this->initCurl(); }
};
$c->setCurlOptions([CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0, CURLOPT_TIMEOUT => 5]);
check('SSL options dropped', !array_key_exists(CURLOPT_SSL_VERIFYPEER, $c->options()) && !array_key_exists(CURLOPT_SSL_VERIFYHOST, $c->options()));
check('other options kept', ($c->options()[CURLOPT_TIMEOUT] ?? null) === 5);
// A real request to a host with a bad certificate must fail. Only when the network is available.
if (getenv('COINSNAP_TEST_NETWORK') === '1') {
    $tlsRefused = function (string $url) use ($c): bool {
        try { $c->request('GET', $url); } catch (ConnectException $e) { return (bool) preg_match('/SSL|certificate/i', $e->getMessage()); }
        return false;
    };
    check('self-signed cert refused', $tlsRefused('https://self-signed.badssl.com/'));
    check('wrong host cert refused', $tlsRefused('https://wrong.host.badssl.com/'));
}

/* ---------- Result objects: array access works on PHP 7.4 too ---------- */
$res = new \Coinsnap\Result\Invoice(['id' => 'inv1', 'status' => 'Settled']);
check('Result array access returns value', (function () use ($res) { try { return $res['status'] === 'Settled' && $res['missing'] === null; } catch (\Throwable $e) { return false; } })());

/* ---------- No global side effects when loading classes ---------- */
check('Invoice.php sends no header', strpos((string) file_get_contents(__DIR__ . '/../library/Client/Invoice.php'), 'Access-Control-Allow-Origin') === false);

echo "$passed passed, $failed failed\n";
exit($failed === 0 ? 0 : 1);
