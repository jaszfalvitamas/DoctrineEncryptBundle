<?php

namespace Ambta\DoctrineEncryptBundle\Subscribers;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Event\PreFlushEventArgs;
use ReflectionClass;
use Doctrine\ORM\Event\PostFlushEventArgs;
use Doctrine\ORM\Events;
use Doctrine\Common\EventSubscriber;
use Doctrine\ORM\Event\LifecycleEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Doctrine\ORM\Event\OnFlushEventArgs;
use Doctrine\Common\Annotations\Reader;
use Doctrine\Common\Util\ClassUtils;
use Ambta\DoctrineEncryptBundle\Encryptors\EncryptorInterface;
use ReflectionProperty;
use Symfony\Component\PropertyAccess\PropertyAccess;

/**
 * Doctrine event subscriber which encrypt/decrypt entities
 */
class DoctrineEncryptSubscriber implements EventSubscriber
{
    /**
     * Appended to end of encrypted value
     */
    const ENCRYPTION_MARKER = '<ENC>';

    /**
     * Encryptor interface namespace
     */
    const ENCRYPTOR_INTERFACE_NS = 'Ambta\DoctrineEncryptBundle\Encryptors\EncryptorInterface';

    /**
     * Encrypted annotation full name
     */
    const ENCRYPTED_ANN_NAME = 'Ambta\DoctrineEncryptBundle\Configuration\Encrypted';

    /**
     * Encryptor
     * @var EncryptorInterface
     */
    private $encryptor;

    /**
     * Annotation reader
     * @var Reader
     */
    private $annReader;

    /**
     * Used for restoring the encryptor after changing it
     * @var string
     */
    private $restoreEncryptor;

    /**
     * Count amount of decrypted values in this service
     * @var integer
     */
    public $decryptCounter = 0;

    /**
     * Count amount of encrypted values in this service
     * @var integer
     */
    public $encryptCounter = 0;

    /** @var array */
    private $cachedDecryptions = [];

    /**
     * Initialization of subscriber
     *
     * @param Reader $annReader
     * @param EncryptorInterface|NULL $encryptor (Optional)  An EncryptorInterface.
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
    public function setEncryptor(EncryptorInterface $encryptor = null)
    {
        $this->encryptor = $encryptor;
    }

    /**
     * Get the current encryptor
     *
     * @return EncryptorInterface returns the encryptor class or null
     */
    public function getEncryptor()
    {
        return $this->encryptor;
    }

    /**
     * Restore encryptor to the one set in the constructor.
     */
    public function restoreEncryptor()
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
     * @param LifecycleEventArgs $liveCycleEventArgs
     */
    public function postUpdate(LifecycleEventArgs $liveCycleEventArgs)
    {
        $entity = $liveCycleEventArgs->getEntity();
        $this->processFields($entity, $liveCycleEventArgs->getEntityManager(), false);
    }

    /**
     * Listen a preUpdate lifecycle event.
     * Encrypt entities property's values on preUpdate, so they will be stored encrypted
     *
     * @param PreUpdateEventArgs $preUpdateEventArgs
     */
    public function preUpdate(PreUpdateEventArgs $preUpdateEventArgs)
    {
        $entity = $preUpdateEventArgs->getEntity();
        $this->processFields($entity, $preUpdateEventArgs->getEntityManager());
    }

    /**
     * Listen a postLoad lifecycle event.
     * Decrypt entities property's values when loaded into the entity manger
     *
     * @param LifecycleEventArgs $liveCycleEventArgs
     */
    public function postLoad(LifecycleEventArgs $liveCycleEventArgs)
    {
        $entity = $liveCycleEventArgs->getEntity();
        $this->processFields($entity, $liveCycleEventArgs->getEntityManager(), false);
    }

    /**
     * Listen to onflush event
     * Encrypt entities that are inserted into the database
     *
     * @param PreFlushEventArgs $preFlushEventArgs
     */
    public function preFlush(PreFlushEventArgs $preFlushEventArgs)
    {
        $unitOfWOrk = $preFlushEventArgs->getEntityManager()->getUnitOfWork();
        foreach ($unitOfWOrk->getIdentityMap() as $entityName => $entityArray) {
            if (isset($this->cachedDecryptions[$entityName])) {
                foreach ($entityArray as $entityId => $instance) {
                    $this->processFields($instance, $preFlushEventArgs->getEntityManager());
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
     */
    public function onFlush(OnFlushEventArgs $onFlushEventArgs)
    {
        $unitOfWork = $onFlushEventArgs->getEntityManager()->getUnitOfWork();
        foreach ($unitOfWork->getScheduledEntityInsertions() as $entity) {
            $encryptCounterBefore = $this->encryptCounter;
            $this->processFields($entity, $onFlushEventArgs->getEntityManager());
            if ($this->encryptCounter > $encryptCounterBefore ) {
                $classMetadata = $onFlushEventArgs->getEntityManager()->getClassMetadata(get_class($entity));
                $unitOfWork->recomputeSingleEntityChangeSet($classMetadata, $entity);
            }
        }
    }

    /**
     * Listen to postFlush event
     * Decrypt entities after having been inserted into the database
     *
     * @param PostFlushEventArgs $postFlushEventArgs
     */
    public function postFlush(PostFlushEventArgs $postFlushEventArgs)
    {
        $unitOfWork = $postFlushEventArgs->getEntityManager()->getUnitOfWork();
        foreach ($unitOfWork->getIdentityMap() as $entityMap) {
            foreach ($entityMap as $entity) {
                $this->processFields($entity, $postFlushEventArgs->getEntityManager(), false);
            }
        }
    }

    /**
     * Realization of EventSubscriber interface method.
     *
     * @return array Return all events which this subscriber is listening
     */
    public function getSubscribedEvents()
    {
        return array(
            Events::postUpdate,
            Events::preUpdate,
            Events::postLoad,
            Events::onFlush,
            Events::preFlush,
            Events::postFlush,
        );
    }

    /**
     * Process (encrypt/decrypt) entities fields
     *
     * @param Object  $entity             doctrine entity
     * @param EntityManagerInterface $em  entity manager
     * @param Boolean $isEncryptOperation If true - encrypt, false - decrypt entity
     *
     * @return object|null
     */
    public function processFields($entity, $em, $isEncryptOperation = true)
    {
        if (!empty($this->encryptor)) {
            // Check which operation to be used
            $encryptorMethod = $isEncryptOperation ? 'encrypt' : 'decrypt';

            $realClass = ClassUtils::getClass($entity);

            $className = get_class($entity);

            $classMetadata = $em->getClassMetadata($className);
            if(null !== $classMetadata) {
                $className = $classMetadata->getName();
            }

            // Get ReflectionClass of our entity
            $properties = $this->getClassProperties($realClass);

            // Foreach property in the reflection class
            foreach ($properties as $refProperty) {
                if ($this->annReader->getPropertyAnnotation($refProperty, 'Doctrine\ORM\Mapping\Embedded')) {
                    $this->handleEmbeddedAnnotation($entity, $refProperty, $em, $isEncryptOperation);
                    continue;
                }

                /**
                 * If property is an normal value and contains the Encrypt tag, lets encrypt/decrypt that property
                 */
                if ($this->annReader->getPropertyAnnotation($refProperty, self::ENCRYPTED_ANN_NAME)) {
                    $pac = PropertyAccess::createPropertyAccessor();
                    $value = $pac->getValue($entity, $refProperty->getName());
                    if ($encryptorMethod === 'decrypt') {
                        if (!empty($value) && substr($value, -strlen(self::ENCRYPTION_MARKER)) === self::ENCRYPTION_MARKER) {
                            $this->decryptCounter++;
                            $currentPropValue = $this->encryptor->decrypt(substr($value, 0, -strlen(self::ENCRYPTION_MARKER)));
                            $pac->setValue($entity, $refProperty->getName(), $currentPropValue);
                            $this->cachedDecryptions[$className][spl_object_id($entity)][$refProperty->getName()][$currentPropValue] = $value;
                        }
                    } else {
                        if (!empty($value)) {
                            if (isset($this->cachedDecryptions[$className][spl_object_id($entity)][$refProperty->getName()][$value])) {
                                $pac->setValue($entity, $refProperty->getName(), $this->cachedDecryptions[$className][spl_object_id($entity)][$refProperty->getName()][$value]);
                            } elseif (substr($value, -strlen(self::ENCRYPTION_MARKER)) !== self::ENCRYPTION_MARKER) {
                                $this->encryptCounter++;
                                $currentPropValue = $this->encryptor->encrypt($value).self::ENCRYPTION_MARKER;
                                $pac->setValue($entity, $refProperty->getName(), $currentPropValue);
                            }
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
     * @param bool               $isEncryptOperation
     */
    private function handleEmbeddedAnnotation($entity, ReflectionProperty $embeddedProperty, $em, bool $isEncryptOperation = true)
    {
        $propName = $embeddedProperty->getName();

        $pac = PropertyAccess::createPropertyAccessor();

        $embeddedEntity = $pac->getValue($entity, $propName);

        if ($embeddedEntity) {
            $this->processFields($embeddedEntity, $em, $isEncryptOperation);
        }
    }

    /**
     * Recursive function to get an associative array of class properties
     * including inherited ones from extended classes
     *
     * @param string $className Class name
     *
     * @return array
     */
    private function getClassProperties($className)
    {
        $reflectionClass = new ReflectionClass($className);
        $properties      = $reflectionClass->getProperties();
        $propertiesArray = array();

        foreach ($properties as $property) {
            $propertyName = $property->getName();
            $propertiesArray[$propertyName] = $property;
        }

        if ($parentClass = $reflectionClass->getParentClass()) {
            $parentPropertiesArray = $this->getClassProperties($parentClass->getName());
            if (count($parentPropertiesArray) > 0) {
                $propertiesArray = array_merge($parentPropertiesArray, $propertiesArray);
            }
        }

        return $propertiesArray;
    }
}
