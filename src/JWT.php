<?php namespace Model\JWT;

use Firebase\JWT\Key;
use Firebase\JWT\JWT as FirebaseJWT;
use Model\Cache\Cache;
use Model\Config\Config;
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
			$cache = Cache::getCacheAdapter($config['type']);

			return $cache->get('model:jwt:key', function (ItemInterface $item) {
				$item->expiresAfter(3600 * 24 * 365);
				return bin2hex(random_bytes(64));
			});
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
					'key' => null,
				];
			} else {
				$newConfig = [
					'type' => 'file',
					'key' => null,
				];
			}

			return "<?php\nreturn " . var_export(['production' => $newConfig], true) . ";\n";
		});
	}
}
