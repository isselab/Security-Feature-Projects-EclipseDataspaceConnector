/*
 *  Copyright (c) 2020 - 2022 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
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

package org.eclipse.edc.connector.api.management.configuration;

import org.eclipse.edc.api.auth.spi.AuthenticationRequestFilter;
import org.eclipse.edc.boot.system.DefaultServiceExtensionContext;
import org.eclipse.edc.boot.system.injection.ObjectFactory;
import org.eclipse.edc.junit.extensions.DependencyInjectionExtension;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.system.ServiceExtensionContext;
import org.eclipse.edc.spi.system.configuration.Config;
import org.eclipse.edc.spi.system.configuration.ConfigFactory;
import org.eclipse.edc.transform.spi.TypeTransformerRegistry;
import org.eclipse.edc.web.jersey.providers.jsonld.JerseyJsonLdInterceptor;
import org.eclipse.edc.web.jersey.providers.jsonld.ObjectMapperProvider;
import org.eclipse.edc.web.spi.WebService;
import org.eclipse.edc.web.spi.configuration.WebServiceConfiguration;
import org.eclipse.edc.web.spi.configuration.WebServiceConfigurer;
import org.gravity.security.annotations.requirements.Critical;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.List;

import static org.eclipse.edc.connector.api.management.configuration.ManagementApiConfigurationExtension.SETTINGS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(DependencyInjectionExtension.class)
@Critical(secrecy = {"ManagementApiConfigurationExtension.initialize(ServiceExtensionContext)"})
class ManagementApiConfigurationExtensionTest {

    private final WebServiceConfigurer configurer = mock();
    private final Monitor monitor = mock();
    private final WebService webService = mock();
    private ManagementApiConfigurationExtension extension;

    @BeforeEach
    void setUp(ServiceExtensionContext context, ObjectFactory factory) {
        TypeTransformerRegistry typeTransformerRegistry = mock();
        when(typeTransformerRegistry.forContext(any())).thenReturn(mock());
        context.registerService(WebService.class, webService);
        context.registerService(WebServiceConfigurer.class, configurer);
        context.registerService(TypeTransformerRegistry.class, typeTransformerRegistry);
        extension = factory.constructInstance(ManagementApiConfigurationExtension.class);
    }

    @Test
    void initialize_shouldConfigureAndRegisterResource() {
        var context = contextWithConfig(ConfigFactory.empty());
        var configuration = WebServiceConfiguration.Builder.newInstance().contextAlias("alias").path("/path").port(1234).build();
        when(configurer.configure(any(), any(), any())).thenReturn(configuration);

        extension.initialize(context);

        verify(configurer).configure(any(), any(), eq(SETTINGS));
        verify(webService).registerResource(eq("alias"), isA(AuthenticationRequestFilter.class));
        verify(webService).registerResource(eq("alias"), isA(JerseyJsonLdInterceptor.class));
        verify(webService).registerResource(eq("alias"), isA(ObjectMapperProvider.class));
    }

    @NotNull
    private DefaultServiceExtensionContext contextWithConfig(Config config) {
        var context = new DefaultServiceExtensionContext(monitor, List.of(() -> config));
        context.initialize();
        return context;
    }
}
