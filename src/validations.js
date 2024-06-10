process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

import * as crypto from 'node:crypto';
import config from "./config.js";
import { createLocalJWKSet, jwtVerify, decodeJwt } from 'jose';

//Calcula o thumbprint do certificado
const getCertThumbprint = function (cert) {
    return crypto.createHash('sha256').update(cert.raw).digest().toString('base64url');
}

//Cria o conteúdo do header authorization de autenticação no formato BasicAuth
const createBasicAuthHeader = function (username, password) {
    const credentials = `${username}:${password}`;
    const encodedCredentials = Buffer.from(credentials).toString('base64');
    return `Basic ${encodedCredentials}`;
}

const introspectAccessToken = async function(bearerToken) {
    try {
        const cleanToken = bearerToken.split(' ')[1];
        const url = config.instrospection.url;

        const formData = new URLSearchParams();
        formData.append('token', cleanToken);

        const requestOptions = {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'authorization': createBasicAuthHeader(config.instrospection.user, config.instrospection.password)
            },
            body: formData,
        };
        const res = await fetch(url, requestOptions);
        const json = await res.json();

        return json;
    } catch (e) {
        console.log("Não foi possível realizar a instropecção do token", bearerToken, e);
        return;
    }
}

//Verifica se:
//1 - Token está ativo
//2 - Contém o escopo necessário para a chamada
//3 - Que o certificado mTLS utilizado na chamada ao endpoint é o mesmo certificado utilizado para gerar o access_token
export const validateClientCredentialsPermissions = function (tokenDetails, clientCert) {
    if (!tokenDetails.active
        || !tokenDetails.scope.split(" ").includes("payments")
        || tokenDetails.cnf['x5t#S256'] !== getCertThumbprint(clientCert)) {
        return false;
    }
    return true;
}

//Obtém o certificado mTLS utilizado pelo cliente
const getClientCertificate = function (req) {
    const pemCert = req.headers['ssl-client-cert'];
    let x509Cert;
    if (pemCert) {
        x509Cert = new crypto.X509Certificate(unescape(pemCert), 'base64');
    } else {
        x509Cert = new crypto.X509Certificate(req.connection.getPeerCertificate(false).raw);	
    }
    return x509Cert;
}

export const validateAuthentication = async function(req) {
    const tokenDetails = await introspectAccessToken(req.headers['authorization']);
    if (!tokenDetails || !validateClientCredentialsPermissions(tokenDetails, getClientCertificate(req))) {
        return null;
    }
    return tokenDetails;
}

export const validatePostHeaders = function(req) {
    if (!req.headers['content-type'].split(';').includes('application/jwt')
    || !req.headers['x-fapi-interaction-id'] 
    || !req.headers['x-idempotency-key'] ) {
        return false;
    }
    return true;
}

export const validateGetHeaders = function(req) {
    if (!req.headers['x-fapi-interaction-id'] ) {
        return false;
    }
    return true;
}

const getClientDetails = async function(clientId) {
	try {
        const url = `${config.clientDetailsUrl}/${clientId}`;
        const res = await fetch(url);
        const json = await res.json();
        return json;
    } catch (e) {
        console.log("Não foi possível obter os detalhes do cliente", clientId, e);
        return;
    }
}

const getClientKeys = async function(url) {
	try {
        const res = await fetch(url);
        const json = await res.json();
        return json;
    } catch (e) {
        console.log("Não foi possível obter os detalhes do cliente", clientId, e);
        return;
    }
}

const validateSignedRequest = async function(clientJwks, clientOrganisationId, signedResponseBody, audience) {
    try {
		const jwks = createLocalJWKSet(clientJwks);

		let result = {};
		result = await jwtVerify(signedResponseBody, jwks, {
			issuer: clientOrganisationId,
			audience: audience,
			clockTolerance: 5,
			maxTokenAge: 300
		});

		return result.payload
	} catch (e) {
		console.log("Erro ao tentar validar a assinatura da requisição", e);
	}
}

const extractOrgIdFromJwksUri = function(url) {
	const urlParts = new URL(url);
	const pathSegments = urlParts.pathname.split('/').filter(segment => segment !== '');
	return pathSegments[0];
}

export const validateRequestSignature = async function(req, clientId, audience) {
	try {
        const client = await getClientDetails(clientId);
        const clientJwks = await getClientKeys(client.jwksUri);
        const clientOrganisationId = extractOrgIdFromJwksUri(client.jwksUri);
        const payload = await validateSignedRequest(clientJwks, clientOrganisationId, req.body, audience);
        return {
            payload,
            clientOrganisationId
        };
	} catch (e) {
		console.log("Erro ao tentar validar os dados da requisição", e);
		return;
	}
}

export const validateGetConsentRequest = async function(req, clientId, db) {
    const payload = db.get(req.params.consentId);
    let clientOrganisationId = 'mock_client_org_id'
    if (config.validateSignature) {
        const client = await getClientDetails(clientId);    
        clientOrganisationId = extractOrgIdFromJwksUri(client.jwksUri);
    }
    return {
        payload,
        clientOrganisationId
    }
}

/*export const validateGetPaymentRequest = async function(req, clientId, db) {
    const payload = db.get(req.params.paymentId);
    let clientOrganisationId = 'mock_client_org_id'
    if (config.validateSignature) {
        const client = await getClientDetails(clientId);    
        clientOrganisationId = extractOrgIdFromJwksUri(client.jwksUri);
    }
    return {
        payload,
        clientOrganisationId
    }
}*/

export const getClientOrganizationId = async function(clientId) {
    const client = await getClientDetails(clientId);    
    const clientOrganisationId = extractOrgIdFromJwksUri(client.jwksUri);
    return clientOrganisationId;
}

export const validateGetRequest = async function(id, clientId, db) {
    const payload = db.get(id);
    let clientOrganisationId;
    
    const client = await getClientDetails(clientId);    
    clientOrganisationId = extractOrgIdFromJwksUri(client.jwksUri);    

    return {
        payload,
        clientOrganisationId
    }
}