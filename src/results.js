import { v4 } from "uuid";
import config from "./config.js";
import * as fidoServer from './conn/fido_server.js'

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

export const createPaymentConsent = async function(payload) {
    const currentDate = new Date();

    let response = {
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
        meta: {
            requestDateTime: currentDate.toISOString()
        }
    }
    response.links = {
        self: `${config.audiencePrefix}/payments/v3/consents/${response.data.consentId}`
    }

    return response;
}

export const createPaymentInitiation = async function(payload, consentId) {
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
    };
    response.links = {
        self: `${config.audiencePrefix}/payments/v3/payments/${response.data.paymentId}`
    };
    response.meta = {
        requestDateTime: currentDate.toISOString()
    };

    return response;
}

export const patchPaymentInitiation = async function(payload, paymentInitiation ) {
    const currentDate = new Date();
    let response = {...paymentInitiation};
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

    return response;
}

export const createEnrollment = function(payload) {
    const currentDate = new Date();

    const response = {...payload};
    response.data.enrollmentId = config.consentIdPrefix + v4();
    response.data.creationDateTime = currentDate;
    response.data.status = 'AWAITING_RISK_SIGNALS';
    response.data.statusUpdateDateTime = currentDate;
    response.links = {
        self: `${config.audiencePrefix}/enrollments/v1/enrollments/${response.data.enrollmentId}`
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

export const postFidoRegistrationOptions = async function(rpId, rpName, platform, enrollmentId) {
    //Busca no servidor FIDO as opções de vínculo de dispositivo
    const fidoRequest = {rpId, rpName, platform, enrollmentId};
    const fidoResponse = await fidoServer.createAttestationOptionsOnFidoServer(fidoRequest);
    
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

export const postFidoRegistration = async function(payload, enrollmentId) {
    const fidoRequest = {...payload.data, enrollmentId};
    const fidoResponse = await fidoServer.createAttestationOnFidoServer(fidoRequest);
    return fidoResponse;
}

export const postFidoSignOption = async function(rpId, rpName, platform, enrollmentId) {
    const fidoRequest = {rpId, rpName, platform, enrollmentId};
    const fidoResponse = await fidoServer.getAssertionOnFidoServer(fidoRequest);

    const currentDate = new Date();
    const response = {
        data: {
            ...fidoResponse
        },
        meta: {
            requestDateTime: currentDate
        }
    };

    return response;
}

export const postFidoSign = async function(payload, enrollmentId) {
    const fidoRequest = { assertion: payload.data.fidoAssertion, enrollmentId};
    const fidoResponse = await fidoServer.checkAssertionOnFidoServer(fidoRequest);

    const currentDate = new Date();
    const response = {
        data: {
            ...fidoResponse
        },
        meta: {
            requestDateTime: currentDate
        }
    };

    return response;
}