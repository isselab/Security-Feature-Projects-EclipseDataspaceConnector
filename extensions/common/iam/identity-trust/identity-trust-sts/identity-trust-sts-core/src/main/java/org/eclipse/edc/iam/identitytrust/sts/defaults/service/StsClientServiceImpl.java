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

package org.eclipse.edc.iam.identitytrust.sts.defaults.service;

import org.eclipse.edc.iam.identitytrust.sts.spi.model.StsClient;
import org.eclipse.edc.iam.identitytrust.sts.spi.service.StsClientService;
import org.eclipse.edc.iam.identitytrust.sts.spi.store.StsClientStore;
import org.eclipse.edc.spi.result.ServiceResult;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.transaction.spi.TransactionContext;
import org.gravity.security.annotations.requirements.Critical;

import java.util.Optional;

import static java.lang.String.format;

@Critical(secrecy={"resolveSecret(String):String"})
public class StsClientServiceImpl implements StsClientService {

    private final StsClientStore stsClientStore;
    private final TransactionContext transactionContext;
    private final Vault vault;

    public StsClientServiceImpl(StsClientStore stsClientStore, Vault vault, TransactionContext transactionContext) {
        this.stsClientStore = stsClientStore;
        this.vault = vault;
        this.transactionContext = transactionContext;
    }

    @Override
    public ServiceResult<StsClient> create(StsClient client) {
        return transactionContext.execute(() -> ServiceResult.from(stsClientStore.create(client)));
    }

    @Override
    public ServiceResult<StsClient> findByClientId(String clientId) {
        return transactionContext.execute(() -> ServiceResult.from(stsClientStore.findByClientId(clientId)));
    }

    @Override
    public ServiceResult<StsClient> authenticate(StsClient client, String secret) {
        return Optional.ofNullable(vault.resolveSecret(client.getSecretAlias()))
                .filter(vaultSecret -> vaultSecret.equals(secret))
                .map(s -> ServiceResult.success(client))
                .orElseGet(() -> ServiceResult.unauthorized(format("Failed to authenticate client with id %s", client.getId())));
    }
}
