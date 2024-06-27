import express from 'express';
import * as validations from './validations.js';
import * as responses from './results.js';
import config from './config.js'
import MemoryAdapter from './persistence.js';
import * as utils from './utils.js'
import * as authServer from './conn/authorization_server.js'

const router = express.Router();
const db = new MemoryAdapter();

router.post('/enrollments/v1/enrollments', async (req, res) => {
    //Obtém detalhes do token via instrospection no AS
    const tokenDetails = await validations.validateAuthentication(req);

    //Verifica que se o access_token é válido
    if (!tokenDetails) {
        res.status(401).json(responses.returnUnauthorised());
        return;
    }

    //Verifica se os headers obrigatórios foram enviados
    if (!validations.validatePostHeaders(req)) {
        res.status(400).json(responses.returnBadRequest());
        return;
    }

    //Cria o audience para validação da assinatura
    const audience = utils.getAudience(config.audiencePrefix, req.route.path);

    //Valida a assinatura da requisição, retorna o payload e o organization id do cliente requisitante para ser utilizado
    //como audience do payload de resposta
    const { payload, clientOrganisationId } = await validations.validateRequestSignature(req, tokenDetails.client_id, audience);
    if (!payload) {
        res.status(400).json(responses.returnBadSignature());
        return;
    } 
    
    //Cria o enrollment
    const enrollment = responses.createEnrollment(payload);
    
    //Salva o enrollment no banco de dados
    db.save(enrollment.data.enrollmentId, enrollment);
    
    //Assina a resposta no formato jwt
    const signedEnrollment = await utils.signPayload(enrollment,clientOrganisationId);
        
    res.status(201)
        .type('application/jwt')
        .set('x-fapi-interaction-id', req.headers['x-fapi-interaction-id'])
        .send(signedEnrollment);
});

router.get('/enrollments/v1/enrollments/:enrollmentId', async (req, res) => {
    //Obtém detalhes do token via instrospection no AS
    const tokenDetails = await validations.validateAuthentication(req);

    //Verifica que se o access_token é válido
    if (!tokenDetails) {
        res.status(401).json(responses.returnUnauthorised());
        return;
    }

    //Verifica se os headers obrigatórios foram enviados
    if (!validations.validateGetHeaders(req)) {
        res.status(400).json(responses.returnBadRequest());
        return;
    }

    //Busca o enrollment no banco de dados
    let enrollment = db.get(req.params.enrollmentId);
    if (!enrollment) {
        res.status(404).json(responses.returnNotFound());
        return;
    }

    //Ajusta a hora da requisição para a hora atual
    enrollment.meta.requestDateTime = (new Date()).toISOString();

    //Busca o organization id do cliente para ser utilizado como audience do payload de resposta
    const clientOrganisationId = await validations.getClientOrganizationId(tokenDetails.client_id);
    
    //Assina a resposta no formato jwt
    const signedEnrollment = await utils.signPayload(enrollment, clientOrganisationId);
        
    res.status(200)
        .type('application/jwt')
        .set('x-fapi-interaction-id', req.headers['x-fapi-interaction-id'])
        .send(signedEnrollment);
});

router.patch('/enrollments/v1/enrollments/:enrollmentId', async (req, res) => {
    //Obtém detalhes do token via instrospection no AS
    const tokenDetails = await validations.validateAuthentication(req);

    //Verifica que se o access_token é válido
    if (!tokenDetails) {
        res.status(401).json(responses.returnUnauthorised());
        return;
    }

    //Verifica se os headers obrigatórios foram enviados
    if (!validations.validateGetHeaders(req)) {
        res.status(400).json(responses.returnBadRequest());
        return;
    }

    //Busca o enrollment no banco de dados
    let enrollment = db.get(req.params.enrollmentId);
    if (!enrollment) {
        res.status(404).json(responses.returnNotFound());
        return;
    }

    //Cria o audience para validação da assinatura
    const params = new Map([[':enrollmentId',req.params.enrollmentId]]);
    const audience = utils.getAudience(config.audiencePrefix, req.route.path, params);

    //Valida a assinatura da requisição, retorna o payload e o organization id do cliente requisitante para ser utilizado
    //como audience do payload de resposta
    const { payload, clientOrganisationId } = await validations.validateRequestSignature(req, tokenDetails.client_id, audience);
    if (!payload) {
        res.status(400).json(responses.returnBadRequest());
        return;
    }
    
    //Atualiza o enrollment com os dados de cancelamento
    enrollment = responses.patchEnrollment(enrollment, payload);

    //Salva no banco de dados
    db.save(enrollment.data.enrollmentId, enrollment);
        
    res.status(204)
        .type('application/jwt')
        .set('x-fapi-interaction-id', req.headers['x-fapi-interaction-id'])
        .send();
});

router.post('/enrollments/v1/enrollments/:enrollmentId/risk-signals', async (req, res) => {
    //Obtém detalhes do token via instrospection no AS
    const tokenDetails = await validations.validateAuthentication(req);

    //Verifica que se o access_token é válido
    if (!tokenDetails) {
        res.status(401).json(responses.returnUnauthorised());
        return;
    }

    //Verifica se os headers obrigatórios foram enviados
    if (!validations.validatePostHeaders(req)) {
        res.status(400).json(responses.returnBadRequest());
        return;
    }

    //Cria o audience para validação da assinatura
    const params = new Map([[':enrollmentId',req.params.enrollmentId]]);
    const audience = utils.getAudience(config.audiencePrefix, req.route.path, params);

    //Valida a assinatura da requisição, retorna o payload e o organization id do cliente requisitante para ser utilizado
    //como audience do payload de resposta
    const { payload, clientOrganisationId } = await validations.validateRequestSignature(req, tokenDetails.client_id, audience);
    if (!payload) {
        res.status(400).json(responses.returnBadSignature());
        return;
    }

    //Busca o enrollment no banco de dados
    let enrollment = db.get(req.params.enrollmentId);
    if (!enrollment) {
        res.status(404).json(responses.returnNotFound());
        return;
    }

    //Atualiza o status do enrollment
    enrollment.data.status = 'AWAITING_ACCOUNT_HOLDER_VALIDATION';
    enrollment.data.statusUpdateDateTime = (new Date()).toISOString();
    
    //Salva no banco de dados
    db.save(enrollment.data.enrollmentId, enrollment);
    
    res.status(204)
        .type('application/jwt')
        .set('x-fapi-interaction-id', req.headers['x-fapi-interaction-id'])
        .send();
    
});

router.post('/enrollments/v1/enrollments/:enrollmentId/fido-registration-options', async (req, res) => {
    //Obtém detalhes do token via instrospection no AS
    const tokenDetails = await validations.validateAuthentication(req);

    //Verifica que se o access_token é válido e se possui o escopo necessário para a chamada
    if (!tokenDetails || !utils.hasScope(tokenDetails, req.params.enrollmentId)) {
        res.status(401).json(responses.returnUnauthorised());
        return;
    }

    //Verifica se os headers obrigatórios foram enviados
    if (!validations.validatePostHeaders(req)) {
        res.status(400).json(responses.returnBadRequest());
        return;
    }

    //Busca o enrollment no banco de dados
    let enrollment = db.get(req.params.enrollmentId);
    if (!enrollment) {
        res.status(404).json(responses.returnNotFound());
        return;
    }

    //Cria o audience para validação da assinatura
    const params = new Map([[':enrollmentId',req.params.enrollmentId]]);
    const audience = utils.getAudience(config.audiencePrefix, req.route.path, params);

    //Valida a assinatura da requisição, retorna o payload e o organization id do cliente requisitante para ser utilizado
    //como audience do payload de resposta
    const { payload, clientOrganisationId } = await validations.validateRequestSignature(req, tokenDetails.client_id, audience);
    if (!payload) {
        res.status(400).json(responses.returnBadSignature());
        return;
    }

    //TODO pegar certificado de cliente, extrair do subjectDN o CN para comparar com o que passado no campo payload.rp
    const clientDN = utils.extractCNFromClientCertificate(req);
    const clientName = await authServer.getClientName(tokenDetails.client_id);
    
    //Busca no servidor FIDO as opções de vínculo de dispositivo
    const fidoRegistrationOptions = await responses.postFidoRegistrationOptions(clientDN, clientName, payload.data.platform, req.params.enrollmentId);

    //Assina a resposta no formato jwt
    const signedFidoRegistrationOptions = await utils.signPayload(fidoRegistrationOptions, clientOrganisationId);
        
    res.status(201)
        .type('application/jwt')
        .set('x-fapi-interaction-id', req.headers['x-fapi-interaction-id'])
        .send(signedFidoRegistrationOptions);
});

router.post('/enrollments/v1/enrollments/:enrollmentId/fido-registration', async (req, res) => {
    //Obtém detalhes do token via instrospection no AS
    const tokenDetails = await validations.validateAuthentication(req);

    //Verifica que se o access_token é válido e se possui o escopo necessário para a chamada
    if (!tokenDetails || !utils.hasScope(tokenDetails, req.params.enrollmentId)) {
        res.status(401).json(responses.returnUnauthorised());
        return;
    }

    //Verifica se os headers obrigatórios foram enviados
    if (!validations.validatePostHeaders(req)) {
        res.status(400).json(responses.returnBadRequest());
        return;
    }

    //Busca o enrollment no banco de dados
    let enrollment = db.get(req.params.enrollmentId);
    if (!enrollment) {
        res.status(404).json(responses.returnNotFound());
        return;
    }

    //Cria o audience para validação da assinatura
    const params = new Map([[':enrollmentId',req.params.enrollmentId]]);
    const audience = utils.getAudience(config.audiencePrefix, req.route.path, params);

    //Valida a assinatura da requisição, retorna o payload e o organization id do cliente requisitante para ser utilizado
    //como audience do payload de resposta
    const { payload, clientOrganisationId } = await validations.validateRequestSignature(req, tokenDetails.client_id, audience);
    if (!payload) {
        res.status(400).json(responses.returnBadSignature());
        return;
    }
   
    //Envia as informações de registro do dispositivo para o servidor FIDO
    const fidoRegistration = await responses.postFidoRegistration(payload, req.params.enrollmentId);

    //Altera o status do enrollment
    enrollment.data.status = "AUTHORISED";
    enrollment.data.statusUpdateDateTime = (new Date()).toISOString();
    db.save(req.params.enrollmentId, enrollment);

    res.status(204).send();
});

router.post('/enrollments/v1/enrollments/:enrollmentId/fido-sign-options', async (req, res) => {
    //Obtém detalhes do token via instrospection no AS
    const tokenDetails = await validations.validateAuthentication(req);

    //Verifica que se o access_token é válido e se possui o escopo necessário para a chamada
    if (!tokenDetails) {
        res.status(401).json(responses.returnUnauthorised());
        return;
    }

    //Verifica se os headers obrigatórios foram enviados
    if (!validations.validatePostHeaders(req)) {
        res.status(400).json(responses.returnBadRequest());
        return;
    }

    //Busca o enrollment no banco de dados
    let enrollment = db.get(req.params.enrollmentId);
    if (!enrollment) {
        res.status(404).json(responses.returnNotFound());
        return;
    }

    //Cria o audience para validação da assinatura
    const params = new Map([[':enrollmentId',req.params.enrollmentId]]);
    const audience = utils.getAudience(config.audiencePrefix, req.route.path, params);

    //Valida a assinatura da requisição, retorna o payload e o organization id do cliente requisitante para ser utilizado
    //como audience do payload de resposta
    const { payload, clientOrganisationId } = await validations.validateRequestSignature(req, tokenDetails.client_id, audience);
    if (!payload) {
        res.status(400).json(responses.returnBadSignature());
        return;
    }

    //TODO pegar certificado de cliente, extrair do subjectDN o CN para comparar com o que passado no campo payload.rp
    const clientDN = utils.extractCNFromClientCertificate(req);
    const clientName = await authServer.getClientName(tokenDetails.client_id);
    
    //Busca no servidor FIDO as opções autenticação
    //const fidoSignOptions = await responses.postFidoSignOption(payload, req.params.enrollmentId);
    //const fidoRegistrationOptions = await responses.postFidoRegistrationOptions(clientDN, clientName, payload.data.platform, req.params.enrollmentId);
    const fidoSignOptions = await responses.postFidoSignOption(clientDN, clientName, payload.data.platform, req.params.enrollmentId);

    //Assina a resposta no formato jwt
    const signedFidoSignOptions = await utils.signPayload(fidoSignOptions, clientOrganisationId);
        
    res.status(201)
        .type('application/jwt')
        .set('x-fapi-interaction-id', req.headers['x-fapi-interaction-id'])
        .send(signedFidoSignOptions);
});

router.post('/enrollments/v1/consents/:consentId/authorise', async (req, res) => {
    //console.log("chegou /enrollments/v1/consents/:consentId/authorise", req.body);
    
    //Obtém detalhes do token via instrospection no AS
    const tokenDetails = await validations.validateAuthentication(req);

    //Verifica que se o access_token é válido e se possui o escopo necessário para a chamada
    if (!tokenDetails) {
        res.status(401).json(responses.returnUnauthorised());
        return;
    }

    //Verifica se os headers obrigatórios foram enviados
    if (!validations.validatePostHeaders(req)) {
        res.status(400).json(responses.returnBadRequest());
        return;
    }

    //Cria o audience para validação da assinatura
    const params = new Map([[':consentId',req.params.consentId]]);
    const audience = utils.getAudience(config.audiencePrefix, req.route.path, params);

    //Valida a assinatura da requisição, retorna o payload e o organization id do cliente requisitante para ser utilizado
    //como audience do payload de resposta
    const { payload, clientOrganisationId } = await validations.validateRequestSignature(req, tokenDetails.client_id, audience);
    if (!payload) {
        res.status(400).json(responses.returnBadSignature());
        return;
    }

    console.log("payload fido sign: ",payload );

    //Busca o enrollment no banco de dados
    let enrollment = db.get(payload.data.enrollmentId);
    if (!enrollment) {
        res.status(404).json(responses.returnNotFound());
        return;
    }

    console.log("enrollment: ", enrollment);
    
    //Valida a autenticação do usuário no servidor FIDO
    const fidoSign = await responses.postFidoSign(payload, enrollment.data.enrollmentId);

    //Assina a resposta no formato jwt
    //const signedFidoSign = await utils.signPayload(fidoSignOptions, clientOrganisationId);
        
    res.status(204)
        .type('application/jwt')
        .set('x-fapi-interaction-id', req.headers['x-fapi-interaction-id'])
        .send();
});

router.post('/payments/v3/consents', async (req, res) => {
    //Obtém detalhes do token via instrospection no AS
    const tokenDetails = await validations.validateAuthentication(req);

    //Verifica que se o access_token é válido
    if (!tokenDetails) {
        res.status(401).json(responses.returnUnauthorised());
        return;
    }

    //Verifica se os headers obrigatórios foram enviados
    if (!validations.validatePostHeaders(req)) {
        res.status(400).json(responses.returnBadRequest());
        return;
    }

    //Cria o audience para validação da assinatura
    const audience = utils.getAudience(config.audiencePrefix, req.route.path);

    //Valida a assinatura da requisição, retorna o payload e o organization id do cliente requisitante para ser utilizado
    //como audience do payload de resposta
    const { payload, clientOrganisationId } = await validations.validateRequestSignature(req, tokenDetails.client_id, audience);
    if (!payload) {
        res.status(400).json(responses.returnBadSignature());
        return;
    } 

    const paymentConsent = await responses.createPaymentConsent(payload);

    //Salva o consentimento no banco de dados
    db.save(paymentConsent.data.consentId, paymentConsent);

    //Assina a resposta no formato jwt
    const signedPaymentconsent = await utils.signPayload(paymentConsent, clientOrganisationId);
        
    res.status(201)
        .type('application/jwt')
        .set('x-fapi-interaction-id', req.headers['x-fapi-interaction-id'])
        .send(signedPaymentconsent);
});

router.get('/payments/v3/consents/:consentId', async (req, res) => {
    //Obtém detalhes do token via instrospection no AS
    const tokenDetails = await validations.validateAuthentication(req);

    //Verifica que se o access_token é válido
    if (!tokenDetails) {
        res.status(401).json(responses.returnUnauthorised());
        return;
    }

    //Verifica se os headers obrigatórios foram enviados
    if (!validations.validatePostHeaders(req)) {
        res.status(400).json(responses.returnBadRequest());
        return;
    }
    
    //Busca o enrollment no banco de dados
    let paymentConsent = db.get(req.params.consentId);
    if (!paymentConsent) {
        res.status(404).json(responses.returnNotFound());
        return;
    }

    //Ajusta a hora da requisição para a hora atual
    paymentConsent.meta.requestDateTime = (new Date()).toISOString();

    //Busca o organization id do cliente para ser utilizado como audience do payload de resposta
    const clientOrganisationId = await validations.getClientOrganizationId(tokenDetails.client_id);
    
    //Assina a resposta no formato jwt
    const signedPaymentConsent = await utils.signPayload(paymentConsent, clientOrganisationId);
        
    res.status(200)
        .type('application/jwt')
        .set('x-fapi-interaction-id', req.headers['x-fapi-interaction-id'])
        .send(signedPaymentConsent);
});

router.post('/payments/v3/pix/payments', async (req, res) => {
    //Obtém detalhes do token via instrospection no AS
    const tokenDetails = await validations.validateAuthentication(req);

    //Verifica que se o access_token é válido e se possui o escopo necessário para a chamada
    if (!tokenDetails) { //|| !utils.hasScope(tokenDetails, req.params.enrollmentId)) { //validar o que fazer aqui pois tem dois tipos de pra validar
        res.status(401).json(responses.returnUnauthorised());
        return;
    }

    //Verifica se os headers obrigatórios foram enviados
    if (!validations.validatePostHeaders(req)) {
        res.status(400).json(responses.returnBadRequest());
        return;
    }
    
    const consentId = utils.extractConsentIdFromScopes(tokenDetails.scope);

    //Cria o audience para validação da assinatura
    const audience = utils.getAudience(config.audiencePrefix, req.route.path);

    //Valida a assinatura da requisição, retorna o payload e o organization id do cliente requisitante para ser utilizado
    //como audience do payload de resposta
    const { payload, clientOrganisationId } = await validations.validateRequestSignature(req, tokenDetails.client_id, audience);
    if (!payload) {
        res.status(400).json(responses.returnBadSignature());
        return;
    }

    const paymentInitiation = await responses.createPaymentInitiation(payload, consentId);

    //Assina a resposta no formato jwt
    const signedPaymentInitiation = await utils.signPayload(paymentInitiation, clientOrganisationId);

    //Salva o consentimento no banco de dados
    db.save(paymentInitiation.data.paymentId, paymentInitiation);

    //mover consentimento para consumed
    let consent = db.get(consentId);
    consent.data.status = "CONSUMED";
    db.save(consentId, consent);
        
     res.status(201)
         .type('application/jwt')
         .set('x-fapi-interaction-id', req.headers['x-fapi-interaction-id'])
         .send(signedPaymentInitiation);
});

router.get('/payments/v3/pix/payments/:paymentId', async (req, res) => {
    //Obtém detalhes do token via instrospection no AS
    const tokenDetails = await validations.validateAuthentication(req);

    //Verifica que se o access_token é válido e se possui o escopo necessário para a chamada
    if (!tokenDetails) { //|| !utils.hasScope(tokenDetails, req.params.enrollmentId)) { //validar o que fazer aqui pois tem dois tipos de pra validar
        res.status(401).json(responses.returnUnauthorised());
        return;
    }

    //Verifica se os headers obrigatórios foram enviados
    if (!validations.validatePostHeaders(req)) {
        res.status(400).json(responses.returnBadRequest());
        return;
    }

    let paymentInitiation = db.get(req.params.paymentId);
    
    //Ajusta a hora da requisição para a hora atual
    paymentInitiation.meta.requestDateTime = (new Date()).toISOString();

    //Busca o organization id do cliente para ser utilizado como audience do payload de resposta
    const clientOrganisationId = await validations.getClientOrganizationId(tokenDetails.client_id);
    
    //Assina a resposta no formato jwt
    const signedPaymentInitiation = await utils.signPayload(paymentInitiation, clientOrganisationId);

    res.status(200)
        .type('application/jwt')
        .set('x-fapi-interaction-id', req.headers['x-fapi-interaction-id'])
        .send(signedPaymentInitiation);
});

router.patch('/payments/v3/pix/payments/:paymentId', async (req, res) => {
    //Obtém detalhes do token via instrospection no AS
    const tokenDetails = await validations.validateAuthentication(req);

    //Verifica que se o access_token é válido e se possui o escopo necessário para a chamada
    if (!tokenDetails) { //|| !utils.hasScope(tokenDetails, req.params.enrollmentId)) { //validar o que fazer aqui pois tem dois tipos de pra validar
        res.status(401).json(responses.returnUnauthorised());
        return;
    }

    //Verifica se os headers obrigatórios foram enviados
    if (!validations.validatePostHeaders(req)) {
        res.status(400).json(responses.returnBadRequest());
        return;
    }

    //Cria o audience para validação da assinatura
    const params = new Map([[':paymentId',req.params.paymentId]]);
    const audience = utils.getAudience(config.audiencePrefix, req.route.path, params);

    //Valida a assinatura da requisição, retorna o payload e o organization id do cliente requisitante para ser utilizado
    //como audience do payload de resposta
    const { payload, clientOrganisationId } = await validations.validateRequestSignature(req, tokenDetails.client_id, audience);
    if (!payload) {
        res.status(400).json(responses.returnBadSignature());
        return;
    }

    const paymentInitiation = db.get(req.params.paymentId);

    const patchPaymentInitiation = await responses.patchPaymentInitiation(payload, paymentInitiation);

    //Assina a resposta no formato jwt
    const signedPatchPaymentInitiation = await utils.signPayload(patchPaymentInitiation, clientOrganisationId);

    res.status(200)
        .type('application/jwt')
        .set('x-fapi-interaction-id', req.headers['x-fapi-interaction-id'])
        .send(signedPatchPaymentInitiation);
});

export default router;