/*
 *  Copyright (c) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
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

package org.eclipse.edc.connector.controlplane.services.spi.protocol;

import org.eclipse.edc.policy.model.Policy;
import org.eclipse.edc.runtime.metamodel.annotation.ExtensionPoint;
import org.eclipse.edc.spi.agent.ParticipantAgent;
import org.eclipse.edc.spi.iam.TokenRepresentation;
import org.eclipse.edc.spi.result.ServiceResult;
import org.eclipse.edc.spi.types.domain.message.RemoteMessage;
import org.gravity.security.annotations.requirements.Critical;

/**
 * Token validator to be used in protocol layer for verifying the token according the
 * input policy and policy scope
 */
@ExtensionPoint
@Critical(secrecy= {"ProtocolTokenValidatorImpl.verify(TokenRepresentation,String,Policy,RemoteMessage):ServiceResult"})
public interface ProtocolTokenValidator {

    /**
     * Verify the {@link TokenRepresentation}
     *
     * @param tokenRepresentation The token
     * @param policyScope         The policy scope
     * @return Returns the extracted {@link ParticipantAgent} if successful, failure otherwise
     */
    default ServiceResult<ParticipantAgent> verify(TokenRepresentation tokenRepresentation, String policyScope) {
        return verify(tokenRepresentation, policyScope, Policy.Builder.newInstance().build(), null);
    }
    
    /**
     * Verify the {@link TokenRepresentation}
     *
     * @param tokenRepresentation The token
     * @param policyScope         The policy scope
     * @param message             The {@link RemoteMessage}
     * @return Returns the extracted {@link ParticipantAgent} if successful, failure otherwise
     */
    default ServiceResult<ParticipantAgent> verify(TokenRepresentation tokenRepresentation, String policyScope, RemoteMessage message) {
        return verify(tokenRepresentation, policyScope, Policy.Builder.newInstance().build(), message);
    }

    /**
     * Verify the {@link TokenRepresentation} in the context of a policy
     *
     * @param tokenRepresentation The token
     * @param policyScope         The policy scope
     * @param policy              The policy
     * @param message             The {@link RemoteMessage}
     * @return Returns the extracted {@link ParticipantAgent} if successful, failure otherwise
     */
    ServiceResult<ParticipantAgent> verify(TokenRepresentation tokenRepresentation, String policyScope, Policy policy, RemoteMessage message);
}
