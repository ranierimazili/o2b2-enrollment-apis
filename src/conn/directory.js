export const getClientKeys = async function(client) {
	try {
        const res = await fetch(client.jwksUri);
        const json = await res.json();
        return json;
    } catch (e) {
        console.log("Não foi possível obter as chaves do cliente", e);
        return;
    }
}