<?php namespace Model\Jwt;

use Composer\InstalledVersions;
use Firebase\JWT\Key;
use Firebase\JWT\JWT as FirebaseJWT;
use Model\Config\Config;

class JWT
{
	private const ALGO = 'RS256';
	private const ENC_PREFIX = 'enc:v1:';

	/**
	 * Builds a token
	 *
	 * @param array $content
	 * @return string
	 */
	public static function build(array $content): string
	{
		return FirebaseJWT::encode(
			$content,
			self::getPrivateKey(),
			self::ALGO
		);
	}

	/**
	 * Verifies and decodes a token
	 *
	 * @param string $stringToken
	 * @return array
	 * @throws \Exception
	 */
	public static function verify(string $stringToken): array
	{
		return (array)FirebaseJWT::decode($stringToken, new Key(self::getPublicKey(), self::ALGO));
	}

	/**
	 * Decodes a token without verifying it
	 *
	 * @param string $stringToken
	 * @return array
	 * @throws \Exception
	 */
	public static function decode(string $stringToken): array
	{
		$token = explode('.', $stringToken);
		if (count($token) !== 3)
			throw new \Exception('A JWT token must be comprised of 3 parts', 400);

		return json_decode(FirebaseJWT::urlsafeB64Decode($token[1]), true, 512, JSON_THROW_ON_ERROR);
	}

	/**
	 * Loads the RSA private key from the configured backend, regenerating the
	 * keypair atomically when missing or legacy.
	 *
	 * @return string
	 * @throws \Exception
	 */
	private static function getPrivateKey(): string
	{
		return self::getKey('private');
	}

	/**
	 * Loads the RSA public key from the configured backend, regenerating the
	 * keypair atomically when missing or legacy.
	 *
	 * @return string
	 * @throws \Exception
	 */
	private static function getPublicKey(): string
	{
		return self::getKey('public');
	}

	/**
	 * Reads the requested key slot from the configured backend. When the slot
	 * is missing or holds a legacy value, regenerates the whole keypair and
	 * persists both slots atomically before returning the requested one.
	 *
	 * @param string $which 'private' or 'public'
	 * @return string
	 * @throws \Exception
	 */
	private static function getKey(string $which): string
	{
		$config = Config::get('jwt');

		switch ($config['type']) {
			case 'fixed':
				$key = $config['key'] ?? null;
				if (!is_array($key) or empty($key['private']) or empty($key['public']))
					throw new \Exception('JWT fixed key must be an array with "private" and "public" PEM entries (RS256). Legacy HS512 string keys are no longer supported.');
				return $key[$which];

			case 'redis':
				if (!InstalledVersions::isInstalled('model/redis'))
					throw new \Exception('Please install model/redis');

				$redisKey = $config['key'] ?? 'model:jwt';
				$stored = self::readSlot($which, \Model\Redis\Redis::get($redisKey . ':' . $which));
				if (!$stored) {
					$keys = self::generateNewKey();
					\Model\Redis\Redis::set($redisKey . ':private', self::wrapForStorage($keys['private']));
					\Model\Redis\Redis::set($redisKey . ':public', $keys['public']);
					if (!empty($config['expire'])) {
						\Model\Redis\Redis::expire($redisKey . ':private', $config['expire']);
						\Model\Redis\Redis::expire($redisKey . ':public', $config['expire']);
					}
					return $keys[$which];
				}

				return $stored;

			case 'file':
				if (empty($config['path']))
					throw new \Exception('Please define a path for JWT key file');

				$projectRoot = realpath(__DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..') . DIRECTORY_SEPARATOR;
				$basePath = $projectRoot . $config['path'];
				$slotPath = $basePath . '.' . $which;

				$rawStored = file_exists($slotPath) ? file_get_contents($slotPath) : null;
				$stored = self::readSlot($which, $rawStored);
				if (!$stored or self::isLegacyKey($stored)) {
					$keys = self::generateNewKey();
					file_put_contents($basePath . '.private', self::wrapForStorage($keys['private']));
					file_put_contents($basePath . '.public', $keys['public']);
					return $keys[$which];
				}
				return $stored;

			case 'db':
				$settingsKey = $config['key'] ?? 'model.jwt.key';
				$stored = self::readSlot($which, \Model\Settings\Settings::get($settingsKey . '.' . $which));
				if (!$stored or self::isLegacyKey($stored)) {
					$keys = self::generateNewKey();
					\Model\Settings\Settings::set($settingsKey . '.private', self::wrapForStorage($keys['private']));
					\Model\Settings\Settings::set($settingsKey . '.public', $keys['public']);
					return $keys[$which];
				}
				return $stored;

			default:
				throw new \Exception('Invalid JWT storage type');
		}
	}

	/**
	 * Normalizes a raw stored slot value: the private slot may be encrypted and
	 * must be unwrapped; the public slot is stored as-is.
	 *
	 * @param string $which
	 * @param string|false|null $rawStored
	 * @return string|null
	 * @throws \Exception
	 */
	private static function readSlot(string $which, string|false|null $rawStored): ?string
	{
		if ($which === 'private')
			return self::unwrapFromStorage($rawStored);

		if ($rawStored === null or $rawStored === false or $rawStored === '')
			return null;
		return $rawStored;
	}

	/**
	 * @param string $stored
	 * @return bool
	 */
	private static function isLegacyKey(string $stored): bool
	{
		return !str_starts_with(ltrim($stored), '-----BEGIN');
	}

	/**
	 * @return array{private: string, public: string}
	 * @throws \Exception
	 */
	private static function generateNewKey(): array
	{
		$resource = openssl_pkey_new([
			'private_key_bits' => 2048,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
		]);
		if (!$resource)
			throw new \Exception('Unable to generate RSA keypair: ' . openssl_error_string());

		if (!openssl_pkey_export($resource, $privateKey))
			throw new \Exception('Unable to export RSA private key: ' . openssl_error_string());

		$details = openssl_pkey_get_details($resource);
		if (!$details or empty($details['key']))
			throw new \Exception('Unable to extract RSA public key: ' . openssl_error_string());

		return [
			'private' => $privateKey,
			'public' => $details['key'],
		];
	}

	/**
	 * Wraps a value before storing it in the configured backend, encrypting it
	 * with the configured "crypt_key" if present. Used only for the private key
	 * slot — public keys are stored as-is since they are not sensitive.
	 *
	 * @param string $value
	 * @return string
	 * @throws \Exception
	 */
	private static function wrapForStorage(string $value): string
	{
		$cryptKey = Config::get('jwt')['crypt_key'] ?? null;
		if (!$cryptKey)
			return $value;

		$key = hash('sha256', $cryptKey, true);
		$iv = random_bytes(12);
		$tag = '';
		$ciphertext = openssl_encrypt($value, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
		if ($ciphertext === false)
			throw new \Exception('Unable to encrypt JWT key: ' . openssl_error_string());

		return self::ENC_PREFIX . base64_encode($iv . $tag . $ciphertext);
	}

	/**
	 * Reverses wrapForStorage. Returns null when the stored value is empty or
	 * does not match the expected (encrypted/plain) shape — signalling the
	 * caller to regenerate. Throws when the configured crypt_key cannot decrypt
	 * an existing encrypted blob, to avoid silently destroying recoverable data.
	 *
	 * @param string|false|null $value
	 * @return string|null
	 * @throws \Exception
	 */
	private static function unwrapFromStorage(string|false|null $value): ?string
	{
		if ($value === null or $value === false or $value === '')
			return null;

		$cryptKey = Config::get('jwt')['crypt_key'] ?? null;
		$isEncrypted = str_starts_with($value, self::ENC_PREFIX);

		if ($cryptKey) {
			if (!$isEncrypted)
				return null; // Pre-existing plaintext key from before crypt_key was set: force regeneration

			$payload = base64_decode(substr($value, strlen(self::ENC_PREFIX)), true);
			if ($payload === false or strlen($payload) < 28)
				throw new \Exception('Stored JWT key is malformed');

			$iv = substr($payload, 0, 12);
			$tag = substr($payload, 12, 16);
			$ciphertext = substr($payload, 28);
			$key = hash('sha256', $cryptKey, true);
			$plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
			if ($plaintext === false)
				throw new \Exception('Unable to decrypt stored JWT key — crypt_key mismatch?');

			return $plaintext;
		}

		if ($isEncrypted)
			throw new \Exception('Stored JWT key is encrypted but no crypt_key is configured');

		return $value;
	}
}
