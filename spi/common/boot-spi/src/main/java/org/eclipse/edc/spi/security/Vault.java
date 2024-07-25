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

package org.eclipse.edc.spi.security;

import org.eclipse.edc.runtime.metamodel.annotation.ExtensionPoint;
import org.eclipse.edc.spi.result.Result;
import org.gravity.security.annotations.requirements.Critical;
import org.gravity.security.annotations.requirements.Secrecy;
import org.jetbrains.annotations.Nullable;

/**
 * Provides secrets such as certificates and keys to the runtime.
 */
@ExtensionPoint
@Critical(secrecy= {"resolveSecret(String):String" ,
	"storeSecret(String,String):Result" })
// &begin[feat_Vault]
public interface Vault {

    /**
     * Resolve the secret for the given key.
     *
     * @param key the key
     * @return the key as a string or null if not found. Binary data will be Base 64 encoded.
     */
    @Nullable
    @Secrecy
    String resolveSecret(String key);

    /**
     * Saves a secret.
     *
     * @param key   the secret key
     * @param value the serialized secret value
     */
    @Secrecy
    Result<Void> storeSecret(String key, String value);

    /**
     * Deletes a secret. Depending on the vault implementation, this might mean a soft delete, or no be even permissible.
     *
     * @param key the secret's key
     */
    Result<Void> deleteSecret(String key);
}
// &end[feat_Vault]
