import { v4 } from "uuid";
import { signPayload } from "./utils.js";
import config from "./config.js";

export const returnUnauthorised = function() {
    const currentDate = new Date();
    return  {
        errors: [{
            code: "UNAUTHORIZED",
            title: "Unauthorised",
            detail: "The authorisation token was not sent or is invalid"
        }],
        meta: {
            requestDateTime: currentDate.toISOString()
        }
    }
}

export const returnBadRequest = function() {
    const currentDate = new Date();
    return {
        errors: [{
            code: "MISSING_MANDATORY_HEADERS",
            title: "Missing mandatory headers",
            detail: "A mandatory header was not sent"
        }],
        meta: {
            requestDateTime: currentDate.toISOString()
        }
    }
}

export const returnNotFound = function() {
    const currentDate = new Date();
    return {
        errors: [{
            code: "RESOURCE_NOT_FOUND",
            title: "Resource not found",
            detail: "Resource not found"
        }],
        meta: {
            requestDateTime: currentDate.toISOString()
        }
    }
}

export const returnBadSignature = function() {
    const currentDate = new Date();
    return {
        errors: [{
            code: "BAD_SIGNATURE",
            title: "Bad signature",
            detail: "Could not verify the message signature"
        }],
        meta: {
            requestDateTime: currentDate.toISOString()
        }
    }
}

export const signGetResponse = async function(payload, clientOrganisationId) {
    const currentDate = new Date();
    payload.meta.requestDateTime = currentDate;
    const signedPayload = await signPayload(payload,clientOrganisationId);
    return signedPayload;
}

export const createPaymentConsentSignedResponse = async function(payload, clientOrganisationId, db) {
    const currentDate = new Date();

    const response = {
        data: {
            consentId: config.consentIdPrefix + v4(),
            creationDateTime: currentDate.toISOString(),
            expirationDateTime: currentDate.toISOString(),
            statusUpdateDateTime: currentDate.toISOString(),
            status: "AWAITING_AUTHORISATION",
            loggedUser: payload.data.loggedUser,
            creditor: payload.data.creditor,
            payment: payload.data.payment,
        },
        links: {
            self: "https://api.banco.com.br/open-banking/api/v1/resource"
        },
        meta: {
            requestDateTime: currentDate.toISOString()
        }
    }
    db.save(response.data.consentId, response);
    const signedPayload = await signPayload(response,clientOrganisationId);
    return signedPayload;
}

export const createPaymentInitiationSignedResponse = async function(payload, clientOrganisationId, consentId, db) {
    const currentDate = new Date();
    let response = { ...payload }
    response.data.paymentId = v4();
    response.data.consentId = consentId;
    response.data.creationDateTime = currentDate.toISOString();
    response.data.statusUpdateDateTime = currentDate.toISOString();
    response.data.status = "RCVD";
    response.data.debtorAccount = {
        ispb: "12345678",
        issuer: "1774",
        number: "1234567890",
        accountType: "CACC"  
    }
    response.links = {
        self: "https://api.banco.com.br/open-banking/api/v1/resource"
    },
    response.meta = {
        requestDateTime: currentDate.toISOString()
    }

    db.save(response.data.paymentId, response);
    const signedPayload = await signPayload(response,clientOrganisationId);
    return signedPayload;
}

export const patchPaymentInitiationSignedResponse = async function(payload, clientOrganisationId, paymentId, db) {
    const currentDate = new Date();
    let response = db.get(paymentId);
    response.data.statusUpdateDateTime = currentDate.toISOString();
    response.data.status = "CANC";
    response.meta = {
        requestDateTime: currentDate.toISOString()
    }
    response.cancellation = {
        reason: "CANCELADO_AGENDAMENTO",
        cancelledFrom: "INICIADORA",
        cancelledAt: currentDate,
        cancelledBy: payload.data.cancellation.cancelledBy
    }

    db.save(paymentId, response);
    const signedPayload = await signPayload(response,clientOrganisationId);
    return signedPayload;
}

export const createEnrollment = function(payload) {
    const currentDate = new Date();

    const response = {...payload};
    response.data.enrollmentId = config.enrollmentIdPrefix + v4();
    response.data.creationDateTime = currentDate;
    response.data.status = 'AWAITING_RISK_SIGNALS';
    response.data.statusUpdateDateTime = currentDate;
    response.links = {
        self: `${config.audiences.createEnrollment}/${response.data.enrollmentId}`
    }
    response.meta = {
        requestDateTime: currentDate.toISOString()
    }
    
    return response;
}

export const patchEnrollment = function(enrollment, payload) {
    const currentDate = new Date();
    
    enrollment.data.cancellation = payload.data.cancellation;
    enrollment.data.cancellation.cancelledFrom = 'INICIADORA';
    enrollment.data.cancellation.rejectedAt = currentDate.toISOString();
    enrollment.data.statusUpdateDateTime = currentDate.toISOString();
    enrollment.data.status = "REVOKED";
    
    return enrollment;
}

/*export const postFidoRegistrationOptionsSignedResponse = async function(payload, clientOrganisationId, enrollmentId, db) {
    const fidoRequest = {...payload.data, enrollmentId};
    const fidoResponse = await createAttestationOnFidoServer(fidoRequest);
    const currentDate = new Date();
    const response = {
        data: {
          enrollmentId: enrollmentId,
          rp: fidoResponse.rp,
          user: {
            id: "string",
            name: "string",
            displayName: "string"
          },
          challenge: fidoResponse.challenge,
          pubKeyCredParams: fidoResponse.pubKeyCredParams,
          timeout: fidoResponse.timeout,
          authenticatorSelection: fidoResponse.authenticatorSelection,
          attestation: fidoResponse.attestation,
        },
        meta: {
          requestDateTime: currentDate
        }
      };
    const signedPayload = await signPayload(response,clientOrganisationId);
    return signedPayload;
}*/

export const postFidoRegistrationOptions = async function(payload, enrollmentId) {
    //Busca no servidor FIDO as opções de vínculo de dispositivo
    const fidoRequest = {...payload.data, enrollmentId};
    const fidoResponse = await createAttestationOnFidoServer(fidoRequest);
    console.log(fidoResponse);
    //Constroi o response body
    const currentDate = new Date();
    const response = {
        data: {
            enrollmentId: enrollmentId,
            rp: fidoResponse.rp,
            user: {
                id: fidoResponse.user.id,
                name: "Nome Completo do Fake User",
                displayName: "Fake User"
            },
            challenge: fidoResponse.challenge,
            pubKeyCredParams: fidoResponse.pubKeyCredParams,
            timeout: fidoResponse.timeout,
            authenticatorSelection: fidoResponse.authenticatorSelection,
            attestation: fidoResponse.attestation,
        },
        meta: {
            requestDateTime: currentDate
        }
    };

    return response;
}


export const postEnrollmentRiskSignals = async function(payload, clientOrganisationId, enrollmentId, db) {
    const currentDate = new Date();
    let response = db.get(enrollmentId);
    response.data.statusUpdateDateTime = currentDate.toISOString();
    response.data.status = "AWAITING_ACCOUNT_HOLDER_VALIDATION";
    db.save(enrollmentId, response);
}

export const postFidoRegistrationSignedResponse = async function(payload, clientOrganisationId, enrollmentId, db) {
    //TODO enviar o conteudo para o servidor FIDO e processar a resposta
}

const createAttestationOnFidoServer = async function(payload) {
    try {
        const url = config.fido.registration_options_endpoint;

        const requestOptions = {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
        };
        const res = await fetch(url, requestOptions);
        const json = await res.json();

        return json;
    } catch (e) {
        console.log("Não foi possível realizar a criação do attestation", e);
        return;
    }
}