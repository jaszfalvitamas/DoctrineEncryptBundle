<?php
declare(strict_types=1);

namespace Ambta\DoctrineEncryptBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\Loader;
use Ambta\DoctrineEncryptBundle\Encryptors\DefuseEncryptor;
use Ambta\DoctrineEncryptBundle\Encryptors\HaliteEncryptor;

/**
 * Initialization of bundle.
 *
 * This is the class that loads and manages your bundle configuration
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html}
 */
class DoctrineEncryptExtension extends Extension
{
    public const SupportedEncryptorClasses = [
        'Defuse' => DefuseEncryptor::class,
        'Halite' => HaliteEncryptor::class,
    ];

    /**
     * {@inheritDoc}
     * @throws \Exception
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        // Create configuration object
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        // If empty encryptor class, use Halite encryptor
        if (\array_key_exists($config['encryptor_class'], self::SupportedEncryptorClasses)) {
            $config['encryptor_class_full'] = self::SupportedEncryptorClasses[$config['encryptor_class']];
        } else {
            $config['encryptor_class_full'] = $config['encryptor_class'];
        }

        // Set parameters
        $container->setParameter('ambta_doctrine_encrypt.encryptor_class_name', $config['encryptor_class_full']);
        $container->setParameter('ambta_doctrine_encrypt.secret_key_path',$config['secret_directory_path'].'/.'.$config['encryptor_class'].'.key');

        // Load service file
        $loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yml');
    }

    /**
     * Get alias for configuration
     *
     * @return string
     */
    public function getAlias(): string
    {
        return 'ambta_doctrine_encrypt';
    }
}
