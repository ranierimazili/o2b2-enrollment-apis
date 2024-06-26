import { SignJWT } from "jose";
import { createPrivateKey } from 'crypto';
import fs from 'fs';
import config from "./config.js";
import { v4 } from "uuid";
import { X509Certificate } from 'node:crypto';
import * as authServer from './conn/authorization_server.js';
import * as crypto from 'node:crypto';

function getPrivateKey() {
    const signingKey = fs.readFileSync(config.sigingKeyPath);
    const key = createPrivateKey(signingKey);
    return key;
}

export const getAudience = function(pathPrefix, pathEndpoint, params) {
    let audience = pathPrefix + pathEndpoint;
    if (params) {
        for (const [key, value] of params) {
            audience = audience.replace(key,value);
        }
    }
    return audience;
}

export const extractConsentIdFromScopes = function(scopes) {
    const scopesArr = scopes.split(' ');
    const index = scopesArr.findIndex(item => item.startsWith(config.consentIdPrefix));
    return scopesArr[index];
}

export const hasScope = function(token, scope) {
    return token.scope.split(' ').includes(`consent:${scope}`);
}

export const signPayload = async function (requestBody, audience) {
    const key = getPrivateKey();

    let signedRequestBody;
    try {
        signedRequestBody = await new SignJWT(requestBody)
        .setProtectedHeader({
          alg: "PS256",
          typ: "JWT",
          kid: config.signingCertKID,
        })
        .setIssuedAt()
        .setIssuer(config.organisationId)
        .setJti(v4())
        .setAudience(audience)
        .setExpirationTime("5m")
        .sign(key);
    } catch (e){
        console.log("Error when trying to sign request body: ", e);
        throw e;
    }

    return signedRequestBody;
}

export const getCertThumbprint = function (cert) {
    return crypto.createHash('sha256').update(cert.raw).digest().toString('base64url');
}

export const getClientCertificate = function (req) {
    const pemCert = req.headers['ssl-client-cert'];
    let x509Cert;
    if (pemCert) {
        x509Cert = new X509Certificate(unescape(pemCert), 'base64');
    } else {
        x509Cert = new X509Certificate(req.connection.getPeerCertificate(false).raw);	
    }
    return x509Cert;
}

export const extractCNFromClientCertificate = function (req) {
    const clientCert = getClientCertificate(req);
    return clientCert.toLegacyObject().subject['CN'];
}

export const extractOrgIdFromJwksUri = function(url) {
	const urlParts = new URL(url);
	const pathSegments = urlParts.pathname.split('/').filter(segment => segment !== '');
	return pathSegments[0];
}

export const getClientOrganizationId = async function(clientId) {
    const client = await authServer.getClientDetails(clientId);    
    const clientOrganisationId = extractOrgIdFromJwksUri(client.jwksUri);
    return clientOrganisationId;
}