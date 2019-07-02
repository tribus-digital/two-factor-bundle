<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Security\TwoFactor\Provider;

use Psr\Log\LoggerInterface;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorToken;
use Scheb\TwoFactorBundle\Security\TwoFactor\Event\TwoFactorAuthenticationEvent;

class TwoFactorProviderPreparationListener
{
    /**
     * @var TwoFactorProviderRegistry
     */
    private $providerRegistry;

    /**
     * @var LoggerInterface|null
     */
    private $logger;

    public function __construct(TwoFactorProviderRegistry $providerRegistry, ?LoggerInterface $logger)
    {
        $this->providerRegistry = $providerRegistry;
        $this->logger = $logger;
    }

    public function onTwoFactorAuthenticationRequest(TwoFactorAuthenticationEvent $event)
    {
        /** @var TwoFactorToken $token */
        $token = $event->getToken();
        $currentProviderName = $token->getCurrentTwoFactorProvider();

        // The two-factor provider was already prepared, nothing to do
        if ($token->isTwoFactorProviderPrepared($currentProviderName)) {
            if ($this->logger) {
                $this->logger->info(sprintf('Two-factor provider %s was already prepared.', $currentProviderName));
            }

            return;
        }

        $user = $token->getUser();
        $this->providerRegistry->getProvider($currentProviderName)->prepareAuthentication($user);
        $token->setTwoFactorProviderPrepared($currentProviderName);

        if ($this->logger) {
            $this->logger->info(sprintf('Two-factor provider %s prepared.', $currentProviderName));
        }
    }
}
