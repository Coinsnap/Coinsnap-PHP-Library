<?php
declare(strict_types=1);
namespace Coinsnap\Client;

use Coinsnap\Http\ClientInterface;
use Coinsnap\Http\CurlClient;

/**
 * Permissions of a BTCPay API key, used by the BTCPay connect callback.
 *
 * Safe use in a connect callback (see the Coinsnap Plugin Security Guide, "Connect callbacks"):
 *
 *   // When the admin clicks "Connect" (capability and anti-forgery token checked there):
 *   $state = BTCPayApiAuthorization::createState();
 *   save_somewhere(BTCPayApiAuthorization::hashState($state)); // add $state to the redirect URL
 *
 *   // In the callback:
 *   $expected = load_and_delete_saved_state_hash();             // one use, even if the check fails
 *   if (!BTCPayApiAuthorization::stateMatches($expected, (string) ($_GET['state'] ?? ''))) { stop(); }
 *   $auth = BTCPayApiAuthorization::fromServer($savedBtcpayUrl, (string) ($_POST['apiKey'] ?? ''));
 *   if ($auth === null || !$auth->isAcceptable()) { stop(); }
 *   save($auth->getApiKey(), $auth->getStoreID());
 *
 * Never build this object from the POSTed permissions: anyone can send those.
 */
class BTCPayApiAuthorization {
	public const REQUIRED_PERMISSIONS = [
		'btcpay.store.canviewinvoices',
		'btcpay.store.cancreateinvoice',
		'btcpay.store.canviewstoresettings',
		'btcpay.store.canmodifyinvoices'
	];
	public const OPTIONAL_PERMISSIONS = [
		'btcpay.store.cancreatenonapprovedpullpayments',
		'btcpay.store.webhooks.canmodifywebhooks',
	];

	/** What a payment plugin needs: create and read invoices, manage its webhook. */
	public const MINIMUM_PERMISSIONS = [
		'btcpay.store.cancreateinvoice',
		'btcpay.store.canviewinvoices',
		'btcpay.store.webhooks.canmodifywebhooks',
	];

	private $apiKey;
	private $permissions;

	/**
	 * @param array $data ['apiKey' => string, 'permissions' => string[]]
	 *
	 * Passing $_POST here is unsafe: the permissions in a POST are whatever the sender wrote.
	 * Use self::fromServer() in a connect callback, which asks BTCPay what the key can do.
	 */
	public function __construct($data) {
		$data = is_array($data) ? $data : [];
		$this->apiKey = isset($data['apiKey']) && is_string($data['apiKey']) ? $data['apiKey'] : null;
		$permissions = isset($data['permissions']) && is_array($data['permissions']) ? $data['permissions'] : [];
		$this->permissions = array_values(array_filter($permissions, 'is_string'));
	}

	/**
	 * Ask the BTCPay server which permissions this key has (GET /api/v1/api-keys/current).
	 *
	 * @param string $btcpayUrl The merchant's BTCPay server URL from the saved settings, never from the request.
	 * @return self|null null when the server does not accept the key or the answer is not usable.
	 * @throws \Coinsnap\Exception\ConnectException when the server cannot be reached.
	 */
	public static function fromServer(string $btcpayUrl, string $apiKey, ?ClientInterface $client = null): ?self {
		$btcpayUrl = rtrim(trim($btcpayUrl), '/');
		if ($btcpayUrl === '' || trim($apiKey) === '' || !preg_match('#^https?://#i', $btcpayUrl)) {
			return null;
		}
		$client = $client ?? new CurlClient();
		$response = $client->request('GET', $btcpayUrl . '/api/v1/api-keys/current', [
			'Accept' => 'application/json',
			'Authorization' => 'token ' . $apiKey,
		]);
		if ($response->getStatus() !== 200) {
			return null;
		}
		$key = json_decode($response->getBody(), true);
		if (!is_array($key) || !isset($key['permissions']) || !is_array($key['permissions'])) {
			return null;
		}
		if (isset($key['apiKey']) && is_string($key['apiKey']) && !hash_equals($key['apiKey'], $apiKey)) {
			return null;
		}
		return new self(['apiKey' => $apiKey, 'permissions' => $key['permissions']]);
	}

	/** A new random state for the BTCPay authorize redirect. Store only its hash (self::hashState()). */
	public static function createState(): string {
		return bin2hex(random_bytes(32));
	}

	public static function hashState(string $state): string {
		return hash('sha256', $state);
	}

	/**
	 * Timing-safe check of the state returned by BTCPay against the hash saved when "Connect" was clicked.
	 * The caller deletes the saved hash before or right after calling this, even if it fails.
	 */
	public static function stateMatches(?string $expectedHash, string $state): bool {
		return is_string($expectedHash) && $expectedHash !== '' && $state !== ''
			&& hash_equals($expectedHash, self::hashState($state));
	}

	public function getApiKey(): ?string
	{
		return $this->apiKey;
	}

	public function getPermissions(): array
	{
		return $this->permissions;
	}

	/** The store ID of the first permission, or '' if there is none. */
	public function getStoreID(): string
	{
		$parts = explode(':', (string) ($this->permissions[0] ?? ''), 2);
		return $parts[1] ?? '';
	}

	/**
	 * Every permission is a store permission (btcpay.store.*) limited to one store
	 * ($storeId if given), and every permission in $needed is granted for that store.
	 * Refuses unrestricted keys, server or user rights, and keys for all stores.
	 */
	public function isAcceptable(array $needed = self::MINIMUM_PERMISSIONS, ?string $storeId = null): bool
	{
		$storeId = $storeId ?? $this->getStoreID();
		if ($this->permissions === [] || $storeId === '' || $this->apiKey === null || $this->apiKey === '') {
			return false;
		}
		foreach ($this->permissions as $permission) {
			$parts = explode(':', $permission, 2);
			if (strpos($parts[0], 'btcpay.store.') !== 0 || ($parts[1] ?? '') !== $storeId) {
				return false;
			}
		}
		foreach ($needed as $permission) {
			if (!in_array($permission . ':' . $storeId, $this->permissions, true)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Exactly REQUIRED_PERMISSIONS, plus any of OPTIONAL_PERMISSIONS. Says nothing about the store;
	 * combine with hasSingleStore(), or use isAcceptable().
	 */
	public function hasRequiredPermissions(): bool
	{
		if ($this->permissions === []) {
			return false;
		}
		$permissions = $this->policies();

		// Remove optional permissions so that only required ones are left.
		$permissions = array_diff($permissions, self::OPTIONAL_PERMISSIONS);

		return empty(array_merge(
			array_diff(self::REQUIRED_PERMISSIONS, $permissions),
			array_diff($permissions, self::REQUIRED_PERMISSIONS)
		));
	}

	/** Every permission is limited to the same, non-empty store ID. False for a key without permissions. */
	public function hasSingleStore(): bool
	{
		if ($this->permissions === []) {
			return false;
		}
		$storeId = null;
		foreach ($this->permissions as $perms) {
			$exploded = explode(':', $perms);
			if (2 !== count($exploded) || $exploded[1] === '') {
				return false;
			}
			if ($storeId === null) {
				$storeId = $exploded[1];
			} elseif ($storeId !== $exploded[1]) {
				return false;
			}
		}

		return true;
	}

	public function hasRefundsPermission(): bool {
		return in_array('btcpay.store.cancreatenonapprovedpullpayments', $this->policies(), true);
	}

	public function hasWebhookPermission(): bool {
		return in_array('btcpay.store.webhooks.canmodifywebhooks', $this->policies(), true);
	}

	/** Permission names without the store ID. */
	private function policies(): array {
		return array_map(static function (string $permission): string {
			return explode(':', $permission)[0];
		}, $this->permissions);
	}
}
