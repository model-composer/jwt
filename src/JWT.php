<?php namespace Model\Jwt;

use Composer\InstalledVersions;
use Firebase\JWT\Key;
use Firebase\JWT\JWT as FirebaseJWT;
use Model\Config\Config;

class JWT
{
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
			self::getKey(),
			'HS512'
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
		return (array)FirebaseJWT::decode($stringToken, new Key(self::getKey(), 'HS512'));
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
	 * @return string
	 * @throws \Exception
	 */
	private static function getKey(): string
	{
		$config = Config::get('jwt');

		switch ($config['type']) {
			case 'fixed':
				return $config['key'];

			case 'redis':
				if (!InstalledVersions::isInstalled('model/redis'))
					throw new \Exception('Please install model/redis');

				$redisKey = $config['key'] ?? 'model.jwt.key';
				$key = \Model\Redis\Redis::get($redisKey);
				if (!$key) {
					$key = self::generateNewKey();
					\Model\Redis\Redis::set($redisKey, $key);
					if (!empty($config['expire']))
						\Model\Redis\Redis::expire($redisKey, $config['expire']);
				}
				return $key;

			case 'file':
				if (empty($config['path']))
					throw new \Exception('Please define a path for JWT key file');

				$projectRoot = realpath(__DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..') . DIRECTORY_SEPARATOR;

				if (file_exists($projectRoot . $config['path'])) {
					return file_get_contents($projectRoot . $config['path']);
				} else {
					$key = self::generateNewKey();
					file_put_contents($projectRoot . $config['path'], $key);
					return $key;
				}

			case 'db':
				$key = \Model\Settings\Settings::get($config['key'] ?? 'model.jwt.key');
				if (!$key) {
					$key = self::generateNewKey();
					\Model\Settings\Settings::set($config['key'] ?? 'model.jwt.key', $key);
				}

				return $key;

			default:
				throw new \Exception('Invalid JWT storage type');
		}
	}

	/**
	 * @return string
	 */
	private static function generateNewKey(): string
	{
		return bin2hex(random_bytes(64));
	}
}
