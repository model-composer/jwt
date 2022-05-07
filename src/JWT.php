<?php namespace Model\JWT;

use Composer\InstalledVersions;
use Firebase\JWT\Key;
use Firebase\JWT\JWT as FirebaseJWT;
use Model\Config\Config;

class JWT
{
	/**
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
	 * @param string $stringToken
	 * @return array|null
	 */
	public static function verify(string $stringToken): ?array
	{
		return (array)FirebaseJWT::decode($stringToken, new Key(self::getKey(), 'HS512'));
	}

	/**
	 * @return string
	 */
	private static function getKey(): string
	{
		$config = self::getConfig();

		switch ($config['type']) {
			case 'fixed':
				return $config['key'];

			case 'redis':
				if (InstalledVersions::isInstalled('model/redis'))
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
				if (InstalledVersions::isInstalled('model/cache'))
					throw new \Exception('Please install model/cache');

				$cache = \Model\Cache\Cache::getCacheAdapter($config['type']);

				return $cache->get('model.jwt.key', function (\Symfony\Contracts\Cache\ItemInterface $item) use ($config) {
					if (!empty($config['expire']))
						$item->expiresAfter($config['expire']);

					return self::generateNewKey();
				});
				break;
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
		return Config::get('jwt', function () {
			return [
				'type' => 'file',
				'key' => null,
				'expire' => 3600 * 24 * 365,
			];
		}, function (string $configFile): ?string {
			require $configFile;

			if ($config['fixed-key']) {
				$newConfig = [
					'type' => 'fixed',
					'key' => $config['fixed-key'],
					'expire' => null,
				];
			} elseif ($config['redis']) {
				$newConfig = [
					'type' => 'redis',
					'key' => null,
					'expire' => 3600 * 24 * 365,
				];
			} else {
				$newConfig = [
					'type' => 'file',
					'key' => null,
					'expire' => 3600 * 24 * 365,
				];
			}

			return "<?php\nreturn " . var_export(['production' => $newConfig], true) . ";\n";
		});
	}
}
