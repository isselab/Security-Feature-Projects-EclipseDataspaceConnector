/*
 *  Copyright (c) 2020 - 2022 Microsoft Corporation
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

package org.eclipse.edc.boot.system.injection.lifecycle;

import org.eclipse.edc.boot.system.injection.InjectionContainer;
import org.eclipse.edc.boot.system.injection.Injector;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.system.ServiceExtension;
import org.eclipse.edc.spi.system.ServiceExtensionContext;
import org.gravity.security.annotations.requirements.Critical;
import org.gravity.security.annotations.requirements.Secrecy;

import static java.lang.String.format;

/**
 * Represents an {@link ServiceExtension}'s lifecycle phase where it's {@linkplain ServiceExtension#initialize(ServiceExtensionContext)} method is invoked by the
 * {@link ExtensionLifecycleManager}.
 */
@Critical(secrecy = {"initialize():void"}, 
  integrity= {"BasicAuthenticationExtension.initialize(ServiceExtensionContext):void"})
public class InitializePhase extends Phase {
    @Secrecy 
	protected InitializePhase(Injector injector, InjectionContainer<ServiceExtension> container, ServiceExtensionContext context, Monitor monitor) {
        super(injector, container, context, monitor);
    } 
    @Secrecy
    protected void initialize() {
        // call initialize
        // &begin[use_feat_ServiceExtension_IdentityAndTrustExtension_InitializePhase]
        // &begin[use_feat_ServiceExtension_BasicAuthenticationExtension_InitializePhase]
        var target = getTarget();
        target.initialize(context);
        // &end[use_feat_ServiceExtension_BasicAuthenticationExtension_InitializePhase]
        // &end[use_feat_ServiceExtension_IdentityAndTrustExtension_InitializePhase]
        var result = container.validate(context);

        // wrap failure message in a more descriptive string
        if (result.failed()) {
            monitor.warning(String.join(", ", format("There were missing service registrations in extension %s: %s", target.getClass(), String.join(", ", result.getFailureMessages()))));
        }
        monitor.info("Initialized " + container.getInjectionTarget().name());
    }
}
