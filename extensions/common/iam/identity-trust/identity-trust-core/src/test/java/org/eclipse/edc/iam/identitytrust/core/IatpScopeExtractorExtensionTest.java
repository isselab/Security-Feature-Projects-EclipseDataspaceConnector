/*
 *  Copyright (c) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Bayerische Motoren Werke Aktiengesellschaft (BMW AG) - initial API and implementation
 *
 */

package org.eclipse.edc.iam.identitytrust.core;

import org.eclipse.edc.iam.identitytrust.core.scope.IatpScopeExtractorFunction;
import org.eclipse.edc.junit.extensions.DependencyInjectionExtension;
import org.eclipse.edc.policy.engine.spi.PolicyEngine;
import org.eclipse.edc.spi.system.ServiceExtensionContext;
import org.gravity.security.annotations.requirements.Critical;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.eclipse.edc.iam.identitytrust.core.IatpScopeExtractorExtension.CATALOG_REQUEST_SCOPE;
import static org.eclipse.edc.iam.identitytrust.core.IatpScopeExtractorExtension.NEGOTIATION_REQUEST_SCOPE;
import static org.eclipse.edc.iam.identitytrust.core.IatpScopeExtractorExtension.TRANSFER_PROCESS_REQUEST_SCOPE;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(DependencyInjectionExtension.class)
@Critical(secrecy= {"IatpScopeExtractorExtension.initialize(ServiceExtensionContext):void",
		"initialize(ServiceExtensionContext, IatpScopeExtractorExtension):void" ,
		"initialize(ServiceExtensionContext):void"}) 
class IatpScopeExtractorExtensionTest {


    private final PolicyEngine policyEngine = mock();

    @BeforeEach
    void setup(ServiceExtensionContext context) {
        context.registerService(PolicyEngine.class, policyEngine);
    }

    @Test
    void initialize(ServiceExtensionContext context, IatpScopeExtractorExtension ext) {

        ext.initialize(context);

        verify(policyEngine).registerPreValidator(eq(CATALOG_REQUEST_SCOPE), isA(IatpScopeExtractorFunction.class));
        verify(policyEngine).registerPreValidator(eq(NEGOTIATION_REQUEST_SCOPE), isA(IatpScopeExtractorFunction.class));
        verify(policyEngine).registerPreValidator(eq(TRANSFER_PROCESS_REQUEST_SCOPE), isA(IatpScopeExtractorFunction.class));
    }


}