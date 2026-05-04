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
			self::getKeys()['private'],
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
		return (array)FirebaseJWT::decode($stringToken, new Key(self::getKeys()['public'], self::ALGO));
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
	 * Loads (and regenerates if missing or legacy) the RSA keypair from the configured backend.
	 *
	 * @return array{private: string, public: string}
	 * @throws \Exception
	 */
	private static function getKeys(): array
	{
		$config = Config::get('jwt');

		switch ($config['type']) {
			case 'fixed':
				$key = $config['key'] ?? null;
				if (!is_array($key) or empty($key['private']) or empty($key['public']))
					throw new \Exception('JWT fixed key must be an array with "private" and "public" PEM entries (RS256). Legacy HS512 string keys are no longer supported.');
				return $key;

			case 'redis':
				if (!InstalledVersions::isInstalled('model/redis'))
					throw new \Exception('Please install model/redis');

				$redisKey = $config['key'] ?? 'model:jwt';
				$storedPrivate = self::unwrapFromStorage(\Model\Redis\Redis::get($redisKey . ':private'));
				$storedPublic = self::unwrapFromStorage(\Model\Redis\Redis::get($redisKey . ':public'));
				if (!$storedPrivate or !$storedPublic) {
					$keys = self::generateNewKey();
					\Model\Redis\Redis::set($redisKey . ':private', self::wrapForStorage($keys['private']));
					\Model\Redis\Redis::set($redisKey . ':public', self::wrapForStorage($keys['public']));
					if (!empty($config['expire'])) {
						\Model\Redis\Redis::expire($redisKey . ':private', $config['expire']);
						\Model\Redis\Redis::expire($redisKey . ':public', $config['expire']);
					}

					return $keys;
				}

				return [
					'private' => $storedPrivate,
					'public' => $storedPublic,
				];

			case 'file':
				if (empty($config['path']))
					throw new \Exception('Please define a path for JWT key file');

				$projectRoot = realpath(__DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..') . DIRECTORY_SEPARATOR;
				$fullPath = $projectRoot . $config['path'];

				$stored = file_exists($fullPath) ? file_get_contents($fullPath) : null;
				$stored = self::unwrapFromStorage($stored);
				if (!$stored or self::isLegacyKey($stored)) {
					$keys = self::generateNewKey();
					file_put_contents($fullPath, self::wrapForStorage(json_encode($keys)));
					return $keys;
				}
				return json_decode($stored, true);

			case 'db':
				$settingsKey = $config['key'] ?? 'model.jwt.key';
				$stored = self::unwrapFromStorage(\Model\Settings\Settings::get($settingsKey));
				if (!$stored or self::isLegacyKey($stored)) {
					$keys = self::generateNewKey();
					\Model\Settings\Settings::set($settingsKey, self::wrapForStorage(json_encode($keys)));
					return $keys;
				}
				return json_decode($stored, true);

			default:
				throw new \Exception('Invalid JWT storage type');
		}
	}

	/**
	 * @param string $stored
	 * @return bool
	 */
	private static function isLegacyKey(string $stored): bool
	{
		$decoded = json_decode($stored, true);
		return !is_array($decoded)
			or empty($decoded['private'])
			or empty($decoded['public'])
			or !str_starts_with(ltrim($decoded['private']), '-----BEGIN')
			or !str_starts_with(ltrim($decoded['public']), '-----BEGIN');
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
	 * with the configured "crypt_key" if present.
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
