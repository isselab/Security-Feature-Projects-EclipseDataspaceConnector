/*
 *  Copyright (c) 2020 - 2024 Microsoft Corporation
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Microsoft Corporation - initial API and implementation
 *       Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
 *
 */

package org.eclipse.edc.boot.system.runtime;

import org.eclipse.edc.boot.system.ServiceLocator;
import org.eclipse.edc.boot.system.testextensions.BaseExtension;
import org.eclipse.edc.spi.EdcException;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.system.ServiceExtension;
import org.eclipse.edc.spi.system.ServiceExtensionContext;
import org.eclipse.edc.spi.system.health.HealthCheckService;
import org.gravity.security.annotations.requirements.Critical;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Critical(secrecy= {"baseRuntime_shouldBoot():void" ,"shouldSetStartupCheckProvider_whenHealthCheckServiceIsRegistered():void" , "BaseRuntime.boot()","baseRuntime_shouldNotBootWithException():void"} )
public class BaseRuntimeTest {

    private final Monitor monitor = mock();
    private final ServiceLocator serviceLocator = mock();
    private final BaseRuntime runtime = new BaseRuntimeFixture(monitor, serviceLocator);

    @Test
    void baseRuntime_shouldBoot() {
        when(serviceLocator.loadImplementors(eq(ServiceExtension.class), anyBoolean())).thenReturn(List.of(new BaseExtension()));

        runtime.boot();

        verify(monitor, never()).severe(anyString(), any());
    }

    @Test
    void baseRuntime_shouldNotBootWithException() {
        var extension = spy(new BaseExtension());

        doThrow(new EdcException("Failed to start base extension")).when(extension).start();
        when(serviceLocator.loadImplementors(eq(ServiceExtension.class), anyBoolean())).thenReturn(List.of(extension));

        assertThatThrownBy(runtime::boot).isInstanceOf(EdcException.class);
        verify(monitor).severe(startsWith("Error booting runtime: Failed to start base extension"), any(EdcException.class));
    }

    @Test
    void shouldSetStartupCheckProvider_whenHealthCheckServiceIsRegistered() {
        var healthCheckService = mock(HealthCheckService.class);
        when(serviceLocator.loadImplementors(eq(ServiceExtension.class), anyBoolean())).thenReturn(List.of(
                new BaseExtension(), registerService(HealthCheckService.class, healthCheckService)));

        runtime.boot();

        verify(healthCheckService).addStartupStatusProvider(any());
        verify(healthCheckService).refresh();
    }

    @NotNull
    private static ServiceExtension registerService(Class<HealthCheckService> serviceClass, HealthCheckService healthCheckService) {
        return new ServiceExtension() {
            @Override
            public void initialize(ServiceExtensionContext context) {
                context.registerService(serviceClass, healthCheckService);
            }
        };
    }

    private static class BaseRuntimeFixture extends BaseRuntime {

        private final Monitor monitor;

        BaseRuntimeFixture(Monitor monitor, ServiceLocator serviceLocator) {
            super(serviceLocator);
            this.monitor = monitor;
        }

        @Override
        protected @NotNull Monitor createMonitor() {
            return monitor;
        }
    }
}
