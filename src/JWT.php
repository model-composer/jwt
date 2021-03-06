<?php namespace Model\JWT;

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
		$config = self::getConfig();

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
				if (!InstalledVersions::isInstalled('model/cache'))
					throw new \Exception('Please install model/cache');

				$cache = \Model\Cache\Cache::getCacheAdapter('file');

				return $cache->get('model.jwt.key', function (\Symfony\Contracts\Cache\ItemInterface $item) use ($config) {
					if (!empty($config['expire']))
						$item->expiresAfter($config['expire']);

					return self::generateNewKey();
				});
		}
	}

	/**
	 * @return string
	 */
	private static function generateNewKey(): string
	{
		return bin2hex(random_bytes(64));
	}

	/**
	 * Config retriever
	 *
	 * @return array
	 * @throws \Exception
	 */
	private static function getConfig(): array
	{
		return Config::get('jwt', [
			[
				'version' => '0.4.0',
				'migration' => function (array $currentConfig, string $env) {
					if ($currentConfig) // Already existing
						return $currentConfig;

					if (defined('INCLUDE_PATH') and file_exists(INCLUDE_PATH . 'app/config/JWT/config.php')) {
						// ModEl 3 migration
						require(INCLUDE_PATH . 'app/config/JWT/config.php');

						if ($config['fixed-key']) {
							return [
								'type' => 'fixed',
								'key' => $config['fixed-key'],
								'expire' => null,
							];
						} elseif ($config['redis']) {
							return [
								'type' => 'redis',
								'key' => null,
								'expire' => null,
							];
						} else {
							return [
								'type' => 'file',
								'key' => null,
								'expire' => null,
							];
						}
					}

					return [
						'type' => 'file',
						'key' => null,
						'expire' => null,
					];
				},
			],
		]);
	}
}
