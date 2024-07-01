import config from "./config.js";
import { createLocalJWKSet, jwtVerify } from 'jose';
import * as authServer from './conn/authorization_server.js';
import * as utils from './utils.js';
import * as directory from './conn/directory.js';

export const validateRequest = async function(req, res, credentialsType, isAudienceValidationNecessary, audienceParams, isIdempotencyValidationNecessary, isPayloadExtractionNecessary) {
    //Obtém detalhes do token via instrospection no AS
    const tokenDetails = await validateAuthentication(req);

    //Verifica que se o access_token é válido
    if (!tokenDetails) {
        res.status(401).json(responses.returnUnauthorised());
        return { success: false, payload: null, clientOrganisationId: null, tokenDetails: null };
    }

    //Verifica se os headers obrigatórios foram enviados
    if (isIdempotencyValidationNecessary) {
        if (!validatePostHeaders(req)) {
            res.status(400).json(responses.returnBadRequest());
            return { success: false, payload: null, clientOrganisationId: null, tokenDetails: null };
        }
    } else {
        if (!validateGetHeaders(req)) {
            res.status(400).json(responses.returnBadRequest());
            return { success: false, payload: null, clientOrganisationId: null, tokenDetails: null };
        }
    }

    let audience = null;
    if (isAudienceValidationNecessary) {
        audience = utils.getAudience(config.audiencePrefix, req.route.path, audienceParams);
    }

    //Valida a assinatura da requisição, retorna o payload e o organization id do cliente requisitante para ser utilizado
    //como audience do payload de resposta
    let payload = null, clientOrganisationId = null;
    if (isPayloadExtractionNecessary) {
        [ payload, clientOrganisationId ] = await validateRequestSignature(req, tokenDetails.client_id, audience);
        if (!payload) {
            res.status(400).json(responses.returnBadRequest());
            return { success: false, payload: null, clientOrganisationId: null, tokenDetails: null };
        }
    }

    return {
        success: true,
        payload,
        clientOrganisationId, 
        tokenDetails
    };
}

//Verifica se:
//1 - Token está ativo
//2 - Contém o escopo necessário para a chamada
//3 - Que o certificado mTLS utilizado na chamada ao endpoint é o mesmo certificado utilizado para gerar o access_token
const validateClientCredentialsPermissions = function (tokenDetails, clientCert) {
    if (!tokenDetails.active
        || !tokenDetails.scope.split(" ").includes("payments")
        || tokenDetails.cnf['x5t#S256'] !== utils.getCertThumbprint(clientCert)) {
        return false;
    }
    return true;
}


const validateAuthentication = async function(req) {
    const tokenDetails = await authServer.introspectAccessToken(req.headers['authorization']);
    if (!tokenDetails || !validateClientCredentialsPermissions(tokenDetails, utils.getClientCertificate(req))) {
        return null;
    }
    return tokenDetails;
}

const validatePostHeaders = function(req) {
    if (!req.headers['content-type'].split(';').includes('application/jwt')
    || !req.headers['x-fapi-interaction-id'] 
    || !req.headers['x-idempotency-key'] ) {
        return false;
    }
    return true;
}

const validateGetHeaders = function(req) {
    if (!req.headers['x-fapi-interaction-id'] ) {
        return false;
    }
    return true;
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

const validateRequestSignature = async function(req, clientId, audience) {
	try {
        const client = await authServer.getClientDetails(clientId);
        const clientJwks = await directory.getClientKeys(client);
        const clientOrganisationId = utils.extractOrgIdFromJwksUri(client.jwksUri);
        const payload = await validateSignedRequest(clientJwks, clientOrganisationId, req.body, audience);
        return [
            payload,
            clientOrganisationId
        ];
	} catch (e) {
		console.log("Erro ao tentar validar os dados da requisição", e);
		return;
	}
}

/*
const validateGetConsentRequest = async function(req, clientId, db) {
    const payload = db.get(req.params.consentId);
    let clientOrganisationId = 'mock_client_org_id'
    if (config.validateSignature) {
        const client = await authServer.getClientDetails(clientId);    
        clientOrganisationId = utils.extractOrgIdFromJwksUri(client.jwksUri);
    }
    return {
        payload,
        clientOrganisationId
    }
}

const validateGetRequest = async function(id, clientId, db) {
    const payload = db.get(id);
    let clientOrganisationId;
    
    const client = await authServer.getClientDetails(clientId);    
    clientOrganisationId = utils.extractOrgIdFromJwksUri(client.jwksUri);    

    return {
        payload,
        clientOrganisationId
    }
}*/