/*
 *  Copyright (c) 2022 Microsoft Corporation
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Microsoft Corporation - Initial implementation
 *
 */

package org.eclipse.edc.keys;

import org.eclipse.edc.keys.spi.KeyParserRegistry;
import org.eclipse.edc.keys.spi.PrivateKeyResolver;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.result.Result;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.spi.system.configuration.Config;
import org.gravity.security.annotations.requirements.Critical;
import org.gravity.security.annotations.requirements.Secrecy;
import org.jetbrains.annotations.NotNull;

import java.security.PrivateKey;

/**
 * Base class for private key resolvers, that handles the parsing of the key, but still leaves the actual resolution (e.g.
 * from a {@link Vault}) up to the inheritor.
 */
@Critical(secrecy= {"KeyParserRegistry.parse(String):Result",
		"AbstractPrivateKeyResolver.resolvePrivateKey(String):Result",
		"IatpDefaultServicesExtensionTest.setup(ServiceExtensionContext):void",
		"Oauth2CredentialsRequestFactoryTest.shouldCreatePrivateKeyRequest_whenPrivateKeyNameIsPresent():void",
		"Oauth2CredentialsRequestFactoryTest.shouldFailIfPrivateKeySecretNotFound():void",
		"Oauth2CredentialsRequestFactory.createAssertion(String,DataAddress):Result",
		"JksPrivateKeyResolverTest.resolve_rsaKey():void",
		 "Oauth2ServiceExtension.createOauth2Service"+
		"(Oauth2ServiceConfiguration,TokenDecoratorRegistry,IdentityProviderKeyResolver):Oauth2ServiceImpl",
		"JksPrivateKeyResolverTest.resolve_ecKey():void",
		"DataPlaneDefaultIamServicesExtension.getPrivateKeySupplier(ServiceExtensionContext):Supplier",
		"IatpDefaultServicesExtension.createDefaultTokenService(ServiceExtensionContext):SecureTokenService", 
		 "StsClientTokenIssuanceIntegrationTest.setup():void",
		 "Oauth2CredentialsRequestFactoryTest.shouldCreatePrivateKeyRequest_whenPrivateKeyNameIsPresent():void",
		 "Oauth2CredentialsRequestFactoryTest.shouldFailIfPrivateKeySecretNotFound():void"})
// &begin[feat_AbstractPrivateKeyResolver]
public abstract class AbstractPrivateKeyResolver implements PrivateKeyResolver {
    private final KeyParserRegistry registry;
    private final Config config;
    private final Monitor monitor;

    public AbstractPrivateKeyResolver(KeyParserRegistry registry, Config config, Monitor monitor) {
        this.registry = registry;
        this.config = config;
        this.monitor = monitor;
    }

    @Override
    @Secrecy
    public Result<PrivateKey> resolvePrivateKey(String id) {
        var encodedKeyResult = resolveInternal(id);

        return encodedKeyResult
                .recover(failure -> {
                    monitor.debug("Public key not found, fallback to config. Error: %s".formatted(failure.getFailureDetail()));
                    return resolveFromConfig(id);
                })
                .compose(encodedKey -> registry.parse(encodedKey).compose(pk -> { // &line[use_feat_KeyParserRegistry_AbstractPrivateKeyResolver_'resolvePrivateKey'] 
                    if (pk instanceof PrivateKey privateKey) {
                        return Result.success(privateKey);
                    } else {
                        var msg = "The specified resource did not contain private key material.";
                        monitor.warning(msg);
                        return Result.failure(msg);
                    }
                }));
    }

    /**
     * Returns the resolved key material
     *
     * @param keyId the Key-ID
     * @return {@link Result#success()} if the key was found, {@link Result#failure(String)} if not found or other error.
     */
    @NotNull
    protected abstract Result<String> resolveInternal(String keyId);

    private Result<String> resolveFromConfig(String keyId) {
        var value = config.getString(keyId, null);
        return value == null ?
                Result.failure("Private key with ID '%s' not found in Config".formatted(keyId)) :
                Result.success(value);
    }
}
// &end[feat_AbstractPrivateKeyResolver]
