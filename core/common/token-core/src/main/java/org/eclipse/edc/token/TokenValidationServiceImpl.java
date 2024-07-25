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

package org.eclipse.edc.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.edc.keys.spi.PublicKeyResolver;
import org.eclipse.edc.security.token.jwt.CryptoConverter;
import org.eclipse.edc.spi.iam.ClaimToken;
import org.eclipse.edc.spi.iam.TokenRepresentation;
import org.eclipse.edc.spi.result.AbstractResult;
import org.eclipse.edc.spi.result.Result;
import org.eclipse.edc.token.spi.TokenValidationRule;
import org.eclipse.edc.token.spi.TokenValidationService;
import org.gravity.security.annotations.requirements.Critical;
import org.gravity.security.annotations.requirements.Secrecy;

import java.security.PublicKey;
import java.text.ParseException;
import java.util.List;
@Critical(secrecy={"validate(TokenRepresentation,PublicKeyResolver, List):Result",
		"resolveKey(String):Result",
		"LocalPublicKeyServiceImpl.resolveKey(String):Result",
		"AbstractPublicKeyResolver.resolveInternal(String):Result",
		"TokenValidationService.validate(TokenRepresentation,PublicKeyResolver,List):Result",
		"verifyJwtToken(TokenRepresentation,VerificationContext):Result" ,
		"IdentityAndTrustExtension.tokenValidationAction():TokenValidationAction" } )
public class TokenValidationServiceImpl implements TokenValidationService {

    public TokenValidationServiceImpl() {
    }

    @Override
    @Secrecy
    public Result<ClaimToken> validate(TokenRepresentation tokenRepresentation, PublicKeyResolver publicKeyResolver, List<TokenValidationRule> rules) {
        var token = tokenRepresentation.getToken();
        var additional = tokenRepresentation.getAdditional();
        try {
            var signedJwt = SignedJWT.parse(token);
            var publicKeyId = signedJwt.getHeader().getKeyID();

            var publicKeyResolutionResult = publicKeyResolver.resolveKey(publicKeyId); // &line[use_feat_LocalPublicKeyServiceImpl_TokenValidationServiceImpl]

            if (publicKeyResolutionResult.failed()) {
                return publicKeyResolutionResult.mapTo();
            }

            var verifierCreationResult = CryptoConverter.createVerifierFor(publicKeyResolutionResult.getContent());

            if (!signedJwt.verify(verifierCreationResult)) {
                return Result.failure("Token verification failed");
            }

            var tokenBuilder = ClaimToken.Builder.newInstance();
            signedJwt.getJWTClaimsSet().getClaims().entrySet().stream()
                    .filter(entry -> entry.getValue() != null)
                    .forEach(entry -> tokenBuilder.claim(entry.getKey(), entry.getValue()));

            var claimToken = tokenBuilder.build();


            var errors = rules.stream()
                    .map(r -> r.checkRule(claimToken, additional))
                    .reduce(Result::merge)
                    .stream()
                    .filter(AbstractResult::failed)
                    .flatMap(r -> r.getFailureMessages().stream())
                    .toList();


            if (!errors.isEmpty()) {
                return Result.failure(errors);
            }

            return Result.success(claimToken);

        } catch (JOSEException e) {
            return Result.failure(e.getMessage());
        } catch (ParseException e) {
            return Result.failure("Failed to decode token");
        }
    }

}
