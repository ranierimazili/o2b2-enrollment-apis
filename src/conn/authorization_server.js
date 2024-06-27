import { decodeJwt } from 'jose';

export const getClientDetails = async function (clientId) {
    const url = `https://localhost:3000/clients/${clientId}`;
    const res = await fetch(url);
    const json = await res.json();
    return json;
}

export const getClientName = async function(clientId) {
    const clientDetails = await getClientDetails(clientId);
    const ssa = decodeJwt(clientDetails.software_statement);
    return ssa.software_client_name;
}