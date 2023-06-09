<?php
declare(strict_types=1);

namespace Ambta\DoctrineEncryptBundle\Subscribers;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Event\PostLoadEventArgs;
use Doctrine\ORM\Event\PostUpdateEventArgs;
use Doctrine\ORM\Event\PreFlushEventArgs;
use ReflectionClass;
use Doctrine\ORM\Event\PostFlushEventArgs;
use Doctrine\ORM\Events;
use Doctrine\Common\EventSubscriber;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Doctrine\ORM\Event\OnFlushEventArgs;
use Doctrine\Common\Annotations\Reader;
use Doctrine\Common\Util\ClassUtils;
use Ambta\DoctrineEncryptBundle\Encryptors\EncryptorInterface;
use ReflectionProperty;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Ambta\DoctrineEncryptBundle\Configuration\Encrypted;
use Doctrine\ORM\Mapping\Embedded;

/**
 * Doctrine event subscriber which encrypt/decrypt entities
 */
class DoctrineEncryptSubscriber implements EventSubscriber
{
    /**
     * Appended to end of encrypted value
     */
    public const ENCRYPTION_MARKER = '<ENC>';

    /**
     * Encryptor interface namespace
     */
    public const ENCRYPTOR_INTERFACE_NS = EncryptorInterface::class;

    /**
     * Encrypted annotation full name
     */
    public const ENCRYPTED_ANN_NAME = Encrypted::class;

    /**
     * Encryptor
     * @var EncryptorInterface
     */
    private EncryptorInterface $encryptor;

    /**
     * Annotation reader
     * @var Reader
     */
    private Reader $annReader;

    /**
     * Used for restoring the encryptor after changing it
     * @var EncryptorInterface|string
     */
    private EncryptorInterface|string $restoreEncryptor;

    /**
     * Count amount of decrypted values in this service
     * @var int
     */
    public int $decryptCounter = 0;

    /**
     * Count amount of encrypted values in this service
     * @var int
     */
    public int $encryptCounter = 0;

    /** @var array */
    private array $cachedDecryptions = [];

    /**
     * Initialization of subscriber
     *
     * @param Reader $annReader
     * @param EncryptorInterface $encryptor (Optional)  An EncryptorInterface.
     */
    public function __construct(Reader $annReader, EncryptorInterface $encryptor)
    {
        $this->annReader = $annReader;
        $this->encryptor = $encryptor;
        $this->restoreEncryptor = $this->encryptor;
    }

    /**
     * Change the encryptor
     *
     * @param EncryptorInterface|null $encryptor
     */
    public function setEncryptor(EncryptorInterface $encryptor = null): void
    {
        $this->encryptor = $encryptor;
    }

    /**
     * Get the current encryptor
     *
     * @return EncryptorInterface returns the encryptor class or null
     */
    public function getEncryptor(): EncryptorInterface
    {
        return $this->encryptor;
    }

    /**
     * Restore encryptor to the one set in the constructor.
     */
    public function restoreEncryptor(): void
    {
        $this->encryptor = $this->restoreEncryptor;
    }

    /**
     * Listen a postUpdate lifecycle event.
     * Decrypt entities property's values when post updated.
     *
     * So for example after form submit the preUpdate encrypted the entity
     * We have to decrypt them before showing them again.
     *
     * @param PostUpdateEventArgs $liveCycleEventArgs
     * @throws \ReflectionException
     */
    public function postUpdate(PostUpdateEventArgs $liveCycleEventArgs): void
    {
        $entity = $liveCycleEventArgs->getObject();
        $this->processFields($entity, $liveCycleEventArgs->getObjectManager(), false);
    }

    /**
     * Listen a preUpdate lifecycle event.
     * Encrypt entities property's values on preUpdate, so they will be stored encrypted
     *
     * @param PreUpdateEventArgs $preUpdateEventArgs
     * @throws \ReflectionException
     */
    public function preUpdate(PreUpdateEventArgs $preUpdateEventArgs): void
    {
        $entity = $preUpdateEventArgs->getObject();
        $this->processFields($entity, $preUpdateEventArgs->getObjectManager());
    }

    /**
     * Listen a postLoad lifecycle event.
     * Decrypt entities property's values when loaded into the entity manger
     *
     * @param PostLoadEventArgs $liveCycleEventArgs
     * @throws \ReflectionException
     */
    public function postLoad(PostLoadEventArgs $liveCycleEventArgs): void
    {
        $entity = $liveCycleEventArgs->getObject();
        $this->processFields($entity, $liveCycleEventArgs->getObjectManager(), false);
    }

    /**
     * Listen to onflush event
     * Encrypt entities that are inserted into the database
     *
     * @param PreFlushEventArgs $preFlushEventArgs
     * @throws \ReflectionException
     */
    public function preFlush(PreFlushEventArgs $preFlushEventArgs): void
    {
        $unit_of_work = $preFlushEventArgs->getObjectManager()->getUnitOfWork();
        foreach ($unit_of_work->getIdentityMap() as $entity_name => $entity_array) {
            if (isset($this->cachedDecryptions[$entity_name])) {
                foreach ($entity_array as $instance) {
                    $this->processFields($instance, $preFlushEventArgs->getObjectManager());
                }
            }
        }
        $this->cachedDecryptions = [];
    }

    /**
     * Listen to onflush event
     * Encrypt entities that are inserted into the database
     *
     * @param OnFlushEventArgs $onFlushEventArgs
     * @throws \ReflectionException
     */
    public function onFlush(OnFlushEventArgs $onFlushEventArgs): void
    {
        $unit_of_work = $onFlushEventArgs->getObjectManager()->getUnitOfWork();
        foreach ($unit_of_work->getScheduledEntityInsertions() as $entity) {
            $encrypt_counter_before = $this->encryptCounter;
            $this->processFields($entity, $onFlushEventArgs->getObjectManager());
            if ($this->encryptCounter > $encrypt_counter_before ) {
                $class_metadata = $onFlushEventArgs->getObjectManager()->getClassMetadata(\get_class($entity));
                $unit_of_work->recomputeSingleEntityChangeSet($class_metadata, $entity);
            }
        }
    }

    /**
     * Listen to postFlush event
     * Decrypt entities after having been inserted into the database
     *
     * @param PostFlushEventArgs $postFlushEventArgs
     * @throws \ReflectionException
     */
    public function postFlush(PostFlushEventArgs $postFlushEventArgs): void
    {
        $unit_of_work = $postFlushEventArgs->getObjectManager()->getUnitOfWork();
        foreach ($unit_of_work->getIdentityMap() as $entity_map) {
            foreach ($entity_map as $entity) {
                $this->processFields($entity, $postFlushEventArgs->getObjectManager(), false);
            }
        }
    }

    /**
     * Realization of EventSubscriber interface method.
     *
     * @return array Return all events which this subscriber is listening
     */
    public function getSubscribedEvents(): array
    {
        return [
            Events::postUpdate,
            Events::preUpdate,
            Events::postLoad,
            Events::onFlush,
            Events::preFlush,
            Events::postFlush,
        ];
    }

    /**
     * Process (encrypt/decrypt) entities fields
     *
     * @param Object $entity doctrine entity
     * @param EntityManagerInterface $em entity manager
     * @param Boolean $isEncryptOperation If true - encrypt, false - decrypt entity
     *
     * @return object|null
     * @throws \ReflectionException
     */
    public function processFields(object $entity, EntityManagerInterface $em, bool $isEncryptOperation = true): ?object
    {
        if (!empty($this->encryptor)) {
            // Check which operation to be used
            $encryptor_method = $isEncryptOperation ? 'encrypt' : 'decrypt';

            $real_class = ClassUtils::getClass($entity);

            $class_name = \get_class($entity);

            $class_metadata = $em->getClassMetadata($class_name);
            if($class_metadata !== null) {
                $class_name = $class_metadata->getName();
            }

            // Get ReflectionClass of our entity
            $properties = $this->getClassProperties($real_class);

            // Foreach property in the reflection class
            foreach ($properties as $ref_property) {
                if ($this->annReader->getPropertyAnnotation($ref_property, Embedded::class)) {
                    $this->handleEmbeddedAnnotation($entity, $ref_property, $em, $isEncryptOperation);
                    continue;
                }

                /**
                 * If property is an normal value and contains the Encrypt tag, lets encrypt/decrypt that property
                 */
                if ($this->annReader->getPropertyAnnotation($ref_property, self::ENCRYPTED_ANN_NAME)) {
                    $pac = PropertyAccess::createPropertyAccessor();
                    $value = $pac->getValue($entity, $ref_property->getName());
                    if ($encryptor_method === 'decrypt') {
                        if (!empty($value) && str_ends_with($value, self::ENCRYPTION_MARKER)) {
                            $this->decryptCounter++;
                            $current_prop_value = $this->encryptor->decrypt(substr($value, 0, -\strlen(self::ENCRYPTION_MARKER)));
                            $pac->setValue($entity, $ref_property->getName(), $current_prop_value);
                            $this->cachedDecryptions[$class_name][spl_object_id($entity)][$ref_property->getName()][$current_prop_value] = $value;
                        }
                    } elseif (!empty($value)) {
                        if (isset($this->cachedDecryptions[$class_name][spl_object_id($entity)][$ref_property->getName()][$value])) {
                            $pac->setValue($entity, $ref_property->getName(), $this->cachedDecryptions[$class_name][spl_object_id($entity)][$ref_property->getName()][$value]);
                        } elseif (!str_ends_with($value, self::ENCRYPTION_MARKER)) {
                            $this->encryptCounter++;
                            $current_prop_value = $this->encryptor->encrypt($value).self::ENCRYPTION_MARKER;
                            $pac->setValue($entity, $ref_property->getName(), $current_prop_value);
                        }
                    }
                }
            }

            return $entity;
        }

        return $entity;
    }

    /**
     * @param                    $entity
     * @param ReflectionProperty $embeddedProperty
     * @param                    $em
     * @param bool $isEncryptOperation
     * @throws \ReflectionException
     */
    private function handleEmbeddedAnnotation($entity, ReflectionProperty $embeddedProperty, $em, bool $isEncryptOperation = true): void
    {
        $prop_name = $embeddedProperty->getName();

        $pac = PropertyAccess::createPropertyAccessor();

        $embedded_entity = $pac->getValue($entity, $prop_name);

        if ($embedded_entity) {
            $this->processFields($embedded_entity, $em, $isEncryptOperation);
        }
    }

    /**
     * Recursive function to get an associative array of class properties
     * including inherited ones from extended classes
     *
     * @param string $className Class name
     *
     * @return array
     * @throws \ReflectionException
     */
    private function getClassProperties(string $className): array
    {
        $reflection_class = new ReflectionClass($className);
        $properties      = $reflection_class->getProperties();
        $properties_array = [];

        foreach ($properties as $property) {
            $property_name = $property->getName();
            $properties_array[$property_name] = $property;
        }

        if ($parent_class = $reflection_class->getParentClass()) {
            $parent_props_array = $this->getClassProperties($parent_class->getName());
            if (count($parent_props_array) > 0) {
                $properties_array = array_merge($parent_props_array, $properties_array);
            }
        }

        return $properties_array;
    }
}
