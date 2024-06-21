import { SignJWT } from "jose";
import { createPrivateKey } from 'crypto';
import fs from 'fs';
import config from "./config.js";
import { v4 } from "uuid";

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