import express from 'express';
import * as validations from './validations.js';
import * as responses from './results.js';
import config from './config.js'
import MemoryAdapter from './persistence.js';
import * as utils from './utils.js'

const router = express.Router();
const db = new MemoryAdapter();

router.post('/enrollments', async (req, res) => {
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
    const audience = utils.getAudience(config.audiences.enrollmentAudiencePrefix, req.route.path);

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

router.get('/enrollments/:enrollmentId', async (req, res) => {
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

router.patch('/enrollments/:enrollmentId', async (req, res) => {
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
    const audience = utils.getAudience(config.audiences.enrollmentAudiencePrefix, req.route.path, params);

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

router.post('/enrollments/:enrollmentId/risk-signals', async (req, res) => {
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
    const audience = utils.getAudience(config.audiences.enrollmentAudiencePrefix, req.route.path, params);

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

router.post('/enrollments/:enrollmentId/fido-registration-options', async (req, res) => {
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
    const audience = utils.getAudience(config.audiences.enrollmentAudiencePrefix, req.route.path, params);

    //Valida a assinatura da requisição, retorna o payload e o organization id do cliente requisitante para ser utilizado
    //como audience do payload de resposta
    const { payload, clientOrganisationId } = await validations.validateRequestSignature(req, tokenDetails.client_id, audience);
    if (!payload) {
        res.status(400).json(responses.returnBadSignature());
        return;
    }
    
    //Busca no servidor FIDO as opções de vínculo de dispositivo
    const fidoRegistrationOptions = await responses.postFidoRegistrationOptions(payload, req.params.enrollmentId);

    //Assina a resposta no formato jwt
    const signedFidoRegistrationOptions = await utils.signPayload(fidoRegistrationOptions, clientOrganisationId);
        
    res.status(201)
        .type('application/jwt')
        .set('x-fapi-interaction-id', req.headers['x-fapi-interaction-id'])
        .send(signedFidoRegistrationOptions);
});
/*
router.post('/enrollments/:enrollmentId/fido-registration', async (req, res) => {
    const tokenDetails = await validateAuthentication(req);

    if (!tokenDetails) {
        res.status(401).json(returnUnauthorised());
        return;
    }

    if (!validatePostHeaders(req)) {
        res.status(400).json(returnBadRequest());
        return;
    }

    const { payload, clientOrganisationId } = await validateRequestBody(req, tokenDetails.client_id, config.audiences.createConsent);
    if (!payload) {
        res.status(400).json(returnBadSignature());
        return;
    } 
    
    const response = await postFidoRegistrationSignedResponse(payload, clientOrganisationId, req.params.enrollmentId, db);
        
    res.status(201)
        .type('application/jwt')
        .set('x-fapi-interaction-id', req.headers['x-fapi-interaction-id'])
        .send(response);
});
*/
export default router;