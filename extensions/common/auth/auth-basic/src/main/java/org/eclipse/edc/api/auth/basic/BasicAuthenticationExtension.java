/*
 *  Copyright (c) 2022 ZF Friedrichshafen AG
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       ZF Friedrichshafen AG - Initial API and Implementation
 *
 */

package org.eclipse.edc.api.auth.basic;

import org.eclipse.edc.api.auth.spi.AuthenticationService;
import org.eclipse.edc.runtime.metamodel.annotation.Extension;
import org.eclipse.edc.runtime.metamodel.annotation.Inject;
import org.eclipse.edc.runtime.metamodel.annotation.Provides;
import org.eclipse.edc.runtime.metamodel.annotation.Setting;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.spi.system.ServiceExtension;
import org.eclipse.edc.spi.system.ServiceExtensionContext;
import org.gravity.security.annotations.requirements.Critical;
import org.gravity.security.annotations.requirements.Integrity;
import org.gravity.security.annotations.requirements.Secrecy;

import java.util.stream.Collectors;

import static java.lang.String.format;

/**
 * Extension that registers an AuthenticationService that uses API Keys
 */
@Provides(AuthenticationService.class)
@Extension(value = "Basic authentication")
@Critical(secrecy= {"ServiceExtension.initialize(ServiceExtensionContext):void",
		"ConfigCredentials(String,String):void" ,
		"BasicAuthenticationExtension.initialize(ServiceExtensionContext):void"},
	integrity= {"vault:Vault",
			"BasicAuthenticationExtension.initialize(ServiceExtensionContext):void",
			"ConfigCredentials.ConfigCredentials(String,String)"})
public class BasicAuthenticationExtension implements ServiceExtension {

    @Setting
    public static final String BASIC_AUTH = "edc.api.auth.basic.vault-keys";
    @Inject
    @Integrity
    private Vault vault;

    @Override
    @Secrecy
    @Integrity
            // &begin[use_feat_ServiceExtension_BasicAuthenticationExtension]
    public void initialize(ServiceExtensionContext context) {
        var monitor = context.getMonitor();

        var credentials = context.getConfig(BASIC_AUTH)
                .getRelativeEntries().entrySet().stream()
                .map(entry -> new ConfigCredentials(entry.getKey(), entry.getValue()))
                .collect(Collectors.toList());

        // Register basic authentication filter
        if (!credentials.isEmpty()) {
            // &begin[use_feat_ServiceExtension_BasicAuthenticationExtension_BasicAuthenticationService]
            var authService = new BasicAuthenticationService(vault, credentials, monitor);
            // &end[use_feat_ServiceExtension_BasicAuthenticationExtension_BasicAuthenticationService]
            context.registerService(AuthenticationService.class, authService);
            monitor.info(format("API Authentication: basic auth configured with %s credential(s)", credentials.size()));
        } else {
            monitor.warning("API Authentication: no basic auth credentials provided");
        }
    }

    // &end[use_feat_ServiceExtension_BasicAuthenticationExtension]
@Critical (secrecy= {"username:String",
		 "vaultKey:String",
		 "ConfigCredentials(String,String):void",
		 "ConfigCredentials.getUsername():String",
		 "ConfigCredentials.getVaultKey():String",
		 "BasicAuthenticationServiceTest.isAuthorized_wrongVaultKey():void",
		 "BasicAuthenticationService.checkBasicAuthValid(Result):boolean",
		 "BasicAuthenticationServiceTest.TEST_CREDENTIALS:List"}, 
		integrity= {"vaultKey:String",  
				"ConfigCredentials(String, String):void",
				"BasicAuthenticationServiceTest.TEST_CREDENTIALS:List",
				"ConfigCredentials.getUsername():String" ,
				"ConfigCredentials.getVaultKey():String"
            })
        // &begin[feat_ConfigCredentials]
static class ConfigCredentials {
        @Secrecy
        private final String username;
        @Secrecy
        @Integrity
        private final String vaultKey;

        @Secrecy
        ConfigCredentials(String username, String vaultKey) {
            this.username = username;
            this.vaultKey = vaultKey;
        }

        @Secrecy
        public String getUsername() {
            return username; 
        }

        @Secrecy
        public String getVaultKey() {
            return vaultKey;
        }
    }
    // &end[feat_ConfigCredentials]
}
