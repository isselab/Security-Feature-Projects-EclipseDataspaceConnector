/*
 *  Copyright (c) 2022 Amadeus
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Amadeus - initial API and implementation
 *       Mercedes-Benz Tech Innovation GmbH - DataEncrypter can be provided by extensions
 *
 */

package org.eclipse.edc.connector.controlplane.transfer.dataplane;

import org.eclipse.edc.connector.api.control.configuration.ControlApiConfiguration;
import org.eclipse.edc.connector.controlplane.transfer.dataplane.api.ConsumerPullTransferTokenValidationApiController;
import org.eclipse.edc.connector.controlplane.transfer.dataplane.flow.ConsumerPullTransferDataFlowController;
import org.eclipse.edc.connector.controlplane.transfer.dataplane.flow.ProviderPushTransferDataFlowController;
import org.eclipse.edc.connector.controlplane.transfer.dataplane.proxy.ConsumerPullDataPlaneProxyResolver;
import org.eclipse.edc.connector.controlplane.transfer.dataplane.spi.security.DataEncrypter;
import org.eclipse.edc.connector.controlplane.transfer.dataplane.spi.token.ConsumerPullTokenExpirationDateFunction;
import org.eclipse.edc.connector.controlplane.transfer.dataplane.validation.ExpirationDateValidationRule;
import org.eclipse.edc.connector.controlplane.transfer.spi.callback.ControlApiUrl;
import org.eclipse.edc.connector.controlplane.transfer.spi.flow.DataFlowManager;
import org.eclipse.edc.connector.dataplane.selector.spi.DataPlaneSelectorService;
import org.eclipse.edc.connector.dataplane.selector.spi.client.DataPlaneClientFactory;
import org.eclipse.edc.keys.spi.LocalPublicKeyService;
import org.eclipse.edc.keys.spi.PrivateKeyResolver;
import org.eclipse.edc.runtime.metamodel.annotation.Extension;
import org.eclipse.edc.runtime.metamodel.annotation.Inject;
import org.eclipse.edc.runtime.metamodel.annotation.Setting;
import org.eclipse.edc.spi.result.Result;
import org.eclipse.edc.spi.system.ServiceExtension;
import org.eclipse.edc.spi.system.ServiceExtensionContext;
import org.eclipse.edc.spi.types.TypeManager;
import org.eclipse.edc.token.JwtGenerationService;
import org.eclipse.edc.token.spi.TokenValidationRulesRegistry;
import org.eclipse.edc.token.spi.TokenValidationService;
import org.eclipse.edc.validator.spi.DataAddressValidatorRegistry;
import org.eclipse.edc.validator.spi.ValidationResult;
import org.eclipse.edc.web.spi.WebService;
import org.gravity.security.annotations.requirements.Critical;
import org.gravity.security.annotations.requirements.Secrecy;
import org.jetbrains.annotations.NotNull;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Clock;
import java.util.function.Supplier;

@Extension(value = TransferDataPlaneCoreExtension.NAME)
@Critical (secrecy= {"AbstractPublicKeyResolver.resolveKey(String):Result<>",
		"privateKeyResolver:PrivateKeyResolver",
		"LocalPublicKeyServiceImpl.resolveKey(String):Result",
		"initialize(ServiceExtensionContext):Result<>",
		"PublicKeyResolver.resolveKey(String):Result<>",
		"TransferDataPlaneCoreExtension.getPrivateKeySupplier(ServiceExtensionContext,String):Supplier",
		 "PublicKeyResolver.resolveKey(String):Result",
		 "AbstractPrivateKeyResolver.resolvePrivateKey(String):Result",
		 "TransferDataPlaneCoreExtensionTest.shouldNotRegisterConsumerPullControllers_whenSettingsAreMissing"+
		 "(TransferDataPlaneCoreExtension,ServiceExtensionContext):void",
		 "TransferDataPlaneCoreExtensionTest.shouldNotRegisterConsumerPullControllers_whenSettingsAreMissing"
		 +"(TransferDataPlaneCoreExtension,ServiceExtensionContext):void"})
// &begin[use_feat_ServiceExtension_TransferDataPlaneCoreExtension]
public class TransferDataPlaneCoreExtension implements ServiceExtension {

    @Setting(value = "Alias of private key used for signing tokens, retrieved from private key resolver")
    public static final String TOKEN_SIGNER_PRIVATE_KEY_ALIAS = "edc.transfer.proxy.token.signer.privatekey.alias";

    @Setting(value = "Alias of public key used for verifying the tokens, retrieved from the vault")
    public static final String TOKEN_VERIFIER_PUBLIC_KEY_ALIAS = "edc.transfer.proxy.token.verifier.publickey.alias";

    public static final String NAME = "Transfer Data Plane Core";
    public static final String TRANSFER_DATAPLANE_TOKEN_CONTEXT = "dataplane-transfer";

    @Inject
    private WebService webService;

    @Inject
    private DataFlowManager dataFlowManager;

    @Inject
    private Clock clock;

    @Inject
    private DataEncrypter dataEncrypter;

    @Inject
    private ControlApiConfiguration controlApiConfiguration;

    @Inject
    private DataPlaneSelectorService selectorService;

    @Inject
    private DataPlaneClientFactory clientFactory;

    @Inject
    private ConsumerPullTokenExpirationDateFunction tokenExpirationDateFunction;

    @Inject(required = false)
    private ControlApiUrl callbackUrl;

    @Inject
    private TypeManager typeManager;

    @Inject
    private LocalPublicKeyService publicKeyService;

    @Inject
    @Secrecy
    private PrivateKeyResolver privateKeyResolver;

    @Inject
    private DataAddressValidatorRegistry dataAddressValidatorRegistry;

    @Inject
    private TokenValidationRulesRegistry tokenValidationRulesRegistry;

    @Inject
    private TokenValidationService tokenValidationService;

    @Override
    public String name() {
        return NAME;
    }

    @Override
    @Secrecy
    public void initialize(ServiceExtensionContext context) {
        var publicKeyAlias = context.getSetting(TOKEN_VERIFIER_PUBLIC_KEY_ALIAS, null);
        var privateKeyAlias = context.getSetting(TOKEN_SIGNER_PRIVATE_KEY_ALIAS, null);

        if (publicKeyAlias != null && privateKeyAlias != null) {
            var controller = new ConsumerPullTransferTokenValidationApiController(tokenValidationService, dataEncrypter, typeManager, (i) -> publicKeyService.resolveKey(publicKeyAlias)); // &line[use_feat_LocalPublicKeyServiceImpl_TransferDataPlaneCoreExtension_'Initialize'] 
            webService.registerResource(controlApiConfiguration.getContextAlias(), controller);

            var resolver = new ConsumerPullDataPlaneProxyResolver(dataEncrypter, typeManager, new JwtGenerationService(), getPrivateKeySupplier(context, privateKeyAlias), () -> publicKeyAlias, tokenExpirationDateFunction);
            dataFlowManager.register(new ConsumerPullTransferDataFlowController(selectorService, resolver));
        } else {
            context.getMonitor().info("One of these settings is not configured, so the connector won't be able to provide 'consumer-pull' transfers: [%s, %s]"
                    .formatted(TOKEN_VERIFIER_PUBLIC_KEY_ALIAS, TOKEN_SIGNER_PRIVATE_KEY_ALIAS));
        }

        tokenValidationRulesRegistry.addRule(TRANSFER_DATAPLANE_TOKEN_CONTEXT, new ExpirationDateValidationRule(clock));

        dataFlowManager.register(new ProviderPushTransferDataFlowController(callbackUrl, selectorService, clientFactory));
        dataAddressValidatorRegistry.registerDestinationValidator("HttpProxy", dataAddress -> ValidationResult.success());
    }

    @NotNull
    @Secrecy
    private Supplier<PrivateKey> getPrivateKeySupplier(ServiceExtensionContext context, String privateKeyAlias) {
        return () -> privateKeyResolver.resolvePrivateKey(privateKeyAlias)
                .orElse(f -> {
                    context.getMonitor().warning("Cannot resolve private key: " + f.getFailureDetail());
                    return null;
                });
    }

}
// &end[use_feat_ServiceExtension_TransferDataPlaneCoreExtension]