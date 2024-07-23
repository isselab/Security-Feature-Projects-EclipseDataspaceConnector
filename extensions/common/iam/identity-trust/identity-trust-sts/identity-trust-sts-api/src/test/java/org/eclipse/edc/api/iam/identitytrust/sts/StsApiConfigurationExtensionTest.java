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

package org.eclipse.edc.api.iam.identitytrust.sts;

import org.eclipse.edc.boot.system.DefaultServiceExtensionContext;
import org.eclipse.edc.junit.extensions.DependencyInjectionExtension;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.system.ServiceExtensionContext;
import org.eclipse.edc.spi.system.configuration.Config;
import org.eclipse.edc.spi.system.configuration.ConfigFactory;
import org.eclipse.edc.web.spi.WebService;
import org.eclipse.edc.web.spi.configuration.WebServiceConfiguration;
import org.eclipse.edc.web.spi.configuration.WebServiceConfigurer;
import org.gravity.security.annotations.requirements.Critical;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.List;

import static org.eclipse.edc.api.iam.identitytrust.sts.StsApiConfigurationExtension.SETTINGS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(DependencyInjectionExtension.class)
@Critical(secrecy= {"ServiceExtension.initialize(ServiceExtensionContext):void"})
public class StsApiConfigurationExtensionTest {

    private final WebServiceConfigurer configurer = mock();
    private final Monitor monitor = mock(Monitor.class);
    private final WebService webService = mock(WebService.class);
    private StsApiConfigurationExtension extension;

    @BeforeEach
    void setUp(ServiceExtensionContext context) {
        context.registerService(WebService.class, webService);
        context.registerService(WebServiceConfigurer.class, configurer);
    }

    @Test
    void initialize_shouldConfigureAndRegisterResource(StsApiConfigurationExtension extension) {
        var context = contextWithConfig(ConfigFactory.empty());
        var configuration = WebServiceConfiguration.Builder.newInstance().contextAlias("alias").path("/path").port(1234).build();
        when(configurer.configure(any(), any(), any())).thenReturn(configuration);

        extension.initialize(context);

        verify(configurer).configure(any(), any(), eq(SETTINGS));
    }

    @NotNull
    private DefaultServiceExtensionContext contextWithConfig(Config config) {
        var context = new DefaultServiceExtensionContext(monitor, List.of(() -> config));
        context.initialize();
        return context;
    }
}
