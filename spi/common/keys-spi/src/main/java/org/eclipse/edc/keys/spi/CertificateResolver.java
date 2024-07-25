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

package org.eclipse.edc.keys.spi;

import org.eclipse.edc.runtime.metamodel.annotation.ExtensionPoint;
import org.gravity.security.annotations.requirements.Critical;
import org.gravity.security.annotations.requirements.Secrecy;
import org.jetbrains.annotations.Nullable;

import java.security.cert.X509Certificate;

/**
 * Resolves X509 certificates.
 */
@ExtensionPoint
@Critical(secrecy= {"Oauth2ServiceExtension.initialize(ServiceExtensionContext):void" ,
		"VaultCertificateResolverTest.resolveCertificate_conversionError():void",
		"VaultCertificateResolverTest.resolveCertificate_notFound():void",
		"Oauth2ServiceExtensionTest.mockCertificate(String):void",
		"Oauth2ServiceExtensionTest.mockCertificate(String):void",
		 "CertificateResolver.resolveCertificate(String):X509Certificate "
		})
// &begin[feat_CertificateResolver]
public interface CertificateResolver {

	/**
	 * Returns the public key associated with the id or null if not found.
	 */
	@Nullable
	@Secrecy
	X509Certificate resolveCertificate(String id);

}
// &end[feat_CertificateResolver]
