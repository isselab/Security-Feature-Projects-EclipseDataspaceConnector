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

package org.eclipse.edc.api.auth.token;

import org.eclipse.edc.api.auth.spi.AuthenticationService;
import org.eclipse.edc.web.spi.exception.AuthenticationFailedException;
import org.gravity.security.annotations.requirements.*;


import java.util.List;
import java.util.Map;
import java.util.Objects;

//&begin[feat_token-auth]
@Critical(secrecy = {"hardCodedApiKey:String" , "TokenBasedAuthenticationService.checkApiKeyValid(List):boolean"}, integrity = {"hardCodedApiKey:String"})
public class TokenBasedAuthenticationService implements AuthenticationService {
    
	
    private static final String API_KEY_HEADER_NAME = "x-api-key";
	@Secrecy
	@Integrity
    private final String hardCodedApiKey; //todo: have a list of API keys?
    @Secrecy
    public TokenBasedAuthenticationService(String hardCodedApiKey) {
        this.hardCodedApiKey = hardCodedApiKey;
    }
 
    /**
     * Checks whether a particular request is authorized based on the "X-Api-Key" header.
     *
     * @param headers The headers, that have to contain the "X-Api-Key" header.
     * @throws IllegalArgumentException The map of headers did not contain the "X-Api-Key" header
     */
    @Secrecy
    @Override
    public boolean isAuthenticated(Map<String, List<String>> headers) {

        Objects.requireNonNull(headers, "headers");

        var apiKey = headers.keySet().stream()
                .filter(k -> k.equalsIgnoreCase(API_KEY_HEADER_NAME))
                .map(headers::get)
                .findFirst();

        return apiKey.map(this::checkApiKeyValid).orElseThrow(() -> new AuthenticationFailedException(API_KEY_HEADER_NAME + " not found"));
    }
    @Secrecy
    private boolean checkApiKeyValid(List<String> apiKeys) {
        return apiKeys.size() == 1 && apiKeys.stream().allMatch(hardCodedApiKey::equalsIgnoreCase);
    }
}
//&end[feat_token-auth]