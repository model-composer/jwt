<?php namespace Model\JWT;

use Firebase\JWT\Key;
use Firebase\JWT\JWT as FirebaseJWT;
use Model\Config\Config;
use Symfony\Component\Cache\Adapter\AbstractAdapter;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Adapter\RedisAdapter;
use Symfony\Contracts\Cache\ItemInterface;

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

		if ($config['type'] === 'fixed') {
			return $config['key'];
		} else {
			$cache = self::getCacheAdapter($config['type']);

			return $cache->get('jwt.key', function (ItemInterface $item) {
				return bin2hex(random_bytes(64));
			});
		}
	}

	/**
	 * @param string $type
	 * @return AbstractAdapter
	 * @throws \Exception
	 */
	private static function getCacheAdapter(string $type): AbstractAdapter
	{
		switch ($type) {
			case 'redis':
				if (!class_exists('\\Model\\Redis\\Redis'))
					throw new \Exception('Please install model/redis');

				$redis = \Model\Redis\Redis::getClient();
				if (!$redis)
					throw new \Exception('Invalid Redis configuration');

				return new RedisAdapter($redis);

			case 'file':
				return new FilesystemAdapter();

			default:
				throw new \Exception('Unrecognized JWT cache type');
		}
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
			];
		}, function (string $configFile): ?string {
			require $configFile;

			if ($config['fixed-key']) {
				$newConfig = [
					'type' => 'fixed',
					'key' => $config['fixed-key'],
				];
			} elseif ($config['redis']) {
				$newConfig = [
					'type' => 'redis',
					'key' => 'jwt-key',
				];
			} else {
				$newConfig = [
					'type' => 'file',
					'key' => null,
				];
			}

			return json_encode($newConfig);
		});
	}
}
