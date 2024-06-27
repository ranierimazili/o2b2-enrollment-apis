import config from "../config.js";

export const createAttestationOptionsOnFidoServer = async function(payload) {
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

export const createAttestationOnFidoServer = async function(payload) {
    try {
        const url = config.fido.registration_endpoint;

        const requestOptions = {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
        };
        
        const res = await fetch(url, requestOptions);
        //const json = await res.json();
        return;

        //return json;
    } catch (e) {
        console.log("Não foi possível realizar a criação do attestation", e);
        return;
    }
}

export const getAssertionOnFidoServer = async function(payload) {
    try {
        const url = config.fido.sign_options;

        const requestOptions = {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
        };
        
        const res = await fetch(url, requestOptions);
        const json = await res.json();
        console.log("getAssertionOnFidoServer: ", json);
        return json;
    } catch (e) {
        console.log("Não foi possível realizar a criação do attestation", e);
        return;
    }
}

export const checkAssertionOnFidoServer = async function(payload) {
    try {
        const url = config.fido.sign;

        const requestOptions = {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
        };
        
        const res = await fetch(url, requestOptions);
        return;
        //const json = await res.json();
        //console.log("checkAssertionOnFidoServer: ", json);
        //return json;
    } catch (e) {
        console.log("Não foi possível realizar a criação do attestation - Mudar erro -  TODO", e);
        return;
    }
}