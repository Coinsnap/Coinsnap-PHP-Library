Coinsnap is a Lightning payment provider and offers a payment gateway for processing Bitcoin and Lightning payments. A merchant only needs a Lightning wallet with a lightning address to accept Bitcoin and Lightning payments on their website.

# Coinsnap PHP Library

Coinsnap API library for PHP 7.4+

This API library is created for PHP developers to connect online store to Coinsnap payment gateway fast and easy. You can include this library inside your plug-in or use it as plugin inside your system.

# 5 steps to receive payments in via Bitcoin/Lightning payment gateway

1. Registration in Coinsnap App
2. Settings saving and payment statuses matching
3. Connecting to Coinsnap App and Webhook saving
4. Invoice and payment link receiving 
5. Payment status update

# 1. Registration in Coinsnap App

Register you account on [Coinsnap App](https://app.coinsnap.io), fill all the necessary fields and receive Store Id and API Key.

# 2. Settings saving and payment statuses matching

You need to save Store Id and API Key in your database as Coinsnap connection configuration. Later you'll add there webhook data. If your store has reserved payment statuses, you can match your payment statuses to Coinsnap's: 
- New - for new invoice
- Processing - for invoice in processing
- Settled - for paid invoice
- Expired - for expired invoice

If you can add Coinsnap payment statuses to existing, you can do it too. It depends of your system.

# 3. Connecting to Coinsnap App and Webhook saving

Every request to Coinsnap App needs necessary headers:

'Accept': 'application/json',
'Content-Type': 'application/json',
'x-api-key': «API Key»

The method Coinsnap\Client\AbstractClient::getRequestHeaders() creates them automatically.

3.1. Check connection to Coinsnap by the method Coinsnap\Client\Store::getStore(«Store ID»).

3.2. If Coinsnap server is available, we can create webhook by the method Coinsnap\Client\Webhook::createWebhook(«Store ID»,«Callback URL»), where «Callback URL» - URL for payment status updates via callback from Coinsnap server.

If webhook is created successfully, you will receive JSON-object with webhook data: {'id', 'secret', 'url'}.
You need to store it in your database as an object or in separate fields.

3.3. You don't need to create webhook every time when you save your connection features, but you can check it by the method Coinsnap\Client\Webhook::findWebhook( «Store ID», «Webhook ID» ) (returns null if the webhook does not exist and throws on an API or network error), or Coinsnap\Client\APIWebhook::checkWebhookExists(). Webhook ID is an id parameter, that you have received early on webhook creation stage. If webhook exists, you don't need to create it again. If the check throws, don't create a new webhook: that would replace the secret on every network glitch. Store the secret under a name only your plugin uses, one per store, and never send it to the browser.

3.4. If your Coinsnap credentians have been changed, you need to update webhook by the method updateWebhook(«Store ID»,«Webhook URL»,«Webhook ID»);
Please save updates webhook data from JSON-object with webhook data: {'id', 'secret', 'url'} over old values.

# 4. Invoice and payment link receiving 

You don't need to change your catalog, basket and order mechanism, but there will be necessary changes on the checkout stage. You your user has chosen "Bitcoin + Lightning" as payment method, you need to request invoice from Coinsnap App by method Coinsnap\Client\Invoice\createInvoice(«Store ID»,«Currency»,«Amount»,«Order ID»,«Buyer e-mail»,«Customer name»,«Redirect URL») in short variant. 

After sending invoice request you will receive payment link and QR-codes for payment in Lightning or Bitcoin. You need to store in order or transaction data received Invoice ID to check payment statuses on fifth step.

# 5. Payment status update

After invoice creation and payment receiving Coinsnap App will connect to callback URL that you have sent to Coinsnap earlier. The body of the request is JSON-object {"type":«Payment status»,"invoiceId":«Invoice ID»}. Never trust the body: it only tells you which invoice to look at.

1. Check the signature over the raw body with Coinsnap\Client\Webhook::checkIncomingWebhookSignature(«Raw body», «X-Coinsnap-Signature header», «Webhook secret»). It returns Webhook::SIGNATURE_OK, SIGNATURE_BAD or SIGNATURE_STALE (timestamp older than 5 minutes); anything but OK: log the reason and reply 401. An empty secret rejects every webhook. The old «X-Coinsnap-Sig» header has no timestamp and should not be used in new code. For BTCPay use Webhook::isIncomingBTCPayWebhookRequestValid() with the «BTCPay-Sig» header.
2. Take only invoiceId from the body and fetch the invoice with Coinsnap\Client\Invoice::findInvoice(«Store ID», «Invoice ID»): it returns the invoice, null if the API does not know it (reply 200 and stop; the dashboard's test webhooks look like this), or throws on an API or network error (reply 503 so the webhook is retried).
3. Mark the order paid only if the API's invoice is Settled, belongs to that order, and its amount and currency match the order. Act once per invoice ID.

# BTCPay connect callback

The BTCPay callback URL is public, so never trust the permissions or store ID in the POST. Create a one-time state with BTCPayApiAuthorization::createState() when the admin clicks "Connect" (store only BTCPayApiAuthorization::hashState($state)), check it in the callback with BTCPayApiAuthorization::stateMatches() and delete it on the first try. Then ask BTCPay what the key can do with BTCPayApiAuthorization::fromServer(«Saved BTCPay URL», «API key») and save the key only if isAcceptable() returns true (every permission limited to one store, with the permissions the plugin needs).

TLS certificate checks are always on in CurlClient; CURLOPT_SSL_VERIFYPEER and CURLOPT_SSL_VERIFYHOST passed to setCurlOptions() are ignored. Use CURLOPT_CAINFO for a custom CA bundle.



