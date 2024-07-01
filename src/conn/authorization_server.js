import { decodeJwt } from 'jose';
import config from "../config.js";

export const getClientDetails = async function(clientId) {
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

export const getClientName = async function(clientId) {
    const clientDetails = await getClientDetails(clientId);
    const ssa = decodeJwt(clientDetails.software_statement);
    return ssa.software_client_name;
}

export const introspectAccessToken = async function(bearerToken) {
    try {
        const cleanToken = bearerToken.split(' ')[1];
        const url = config.introspection.url;

        const formData = new URLSearchParams();
        formData.append('token', cleanToken);

        const requestOptions = {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'authorization': 'Basic ' + Buffer.from(`${config.introspection.user}:${config.introspection.password}`).toString('base64')
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