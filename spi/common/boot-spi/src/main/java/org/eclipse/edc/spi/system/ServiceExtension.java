/*
 *  Copyright (c) 2020, 2021 Microsoft Corporation
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Microsoft Corporation - initial API and implementation
 *
 */

package org.eclipse.edc.spi.system;

import org.gravity.security.annotations.requirements.Critical;
import org.gravity.security.annotations.requirements.Secrecy;

/**
 * Contributes services used by the runtime.
 * Service extensions are started after system boostrap.
 */
@Critical( secrecy= {"InitializePhase.initialize():void",
		 "ServiceExtension.initialize(ServiceExtensionContext):void",  
		"IatpScopeExtractorExtensionTest.initialize(ServiceExtensionContext, IatpScopeExtractorExtension):void",
		"StsClientConfigurationExtensionTest.initialize_noClients(ServiceExtensionContext,StsClientConfigurationExtension):void" ,
		"testPrimaryMethod_loadKeyFromVault(ServiceExtensionContext, TokenBasedAuthenticationExtension):void",
		"StsRemoteClientExtensionTest.initialize(StsRemoteClientExtension, ServiceExtensionContext):void",
		"SqlAssetIndexServiceExtensionTest.shouldInitializeTheStore(SqlAssetIndexServiceExtension,ServiceExtensionContext):void",
		"HashicorpVaultExtensionTest.start_withTokenRenewDisabled_shouldNotStartTokenRenewTask(ServiceExtensionContext):void",
		"HashicorpVaultExtensionTest.shutdown_withTokenRenewTaskRunning_shouldStopTokenRenewTask(ServiceExtensionContext):void",
		"HashicorpVaultExtensionTest.start_withTokenRenewEnabled_shouldStartTokenRenewTask(ServiceExtensionContext):void",
		"HashicorpVaultExtensionTest.shutdown_withTokenRenewTaskNotRunning_shouldNotStopTokenRenewTask(ServiceExtensionContext):void",
		"StsDefaultStoresExtensionTest.initialize(StsDefaultStoresExtension,ServiceExtensionContext):void",
		"StsClientConfigurationExtensionTest.initialize_withClient(ServiceExtensionContext,StsClientConfigurationExtension):void",
		"SecureTokenServiceApiExtensionTest.initialize(ServiceExtensionContext,SecureTokenServiceApiExtension):void",
		"StsDefaultStoresExtensionTest.initialize(StsDefaultStoresExtension,ServiceExtensionContext):void",
		"StsRemoteClientExtensionTest.initialize(StsRemoteClientExtension,ServiceExtensionContext):void",
		"StsRemoteClientConfigurationExtensionTest.initialize(StsRemoteClientConfigurationExtension,ServiceExtensionContext,Vault):void"})

// &begin[feat_ServiceExtension]
public interface ServiceExtension extends SystemExtension {

	/** 
	 * Initializes the extension.
	 */
	@Secrecy
	default void initialize(ServiceExtensionContext context) {
	}

	/**
	 * Signals the extension to prepare for the runtime to receive requests.
	 */
	default void start() {
	}

	/**
	 * Signals the extension to release resources and shutdown.
	 */
	default void shutdown() {
	}

    /**
     * Hook method to perform some additional preparatory work before the extension is started.
     * All dependencies are guaranteed to be resolved, and all other extensions are guaranteed to have completed initialization.
     * <p>
     * Typical use cases include wanting to wait until all registrations of a {@code *Registry} have completed, perform some additional
     * checking whether a service exists or not, etc.
     * <p>
     * <strong>Do NOT perform any service registration in this method!</strong>
     */
    default void prepare() {
    }
}
// &end[feat_ServiceExtension]
