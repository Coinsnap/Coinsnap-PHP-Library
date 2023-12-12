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



# 4. Invoice and payment link receiving 



# 5. Payment status update



