<?php namespace Model\Jwt;

use Model\Config\AbstractConfigProvider;

class ConfigProvider extends AbstractConfigProvider
{
	public static function migrations(): array
	{
		return [
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
		];
	}
}
