import 'dotenv/config'

export default {
    serverPort: process.env.SERVER_PORT || 4001,
    instrospection: {
        url: process.env.INTROSPECTION_ENDPOINT,
        user: process.env.INTROSPECTION_USER,
        password: process.env.INTROSPECTION_PASSWORD
    },
    organisationId: process.env.ORGANISATION_ID,
    signingCertKID: process.env.SIGNING_CERT_KID,
    sigingKeyPath: process.env.SIGNING_KEY_PATH,
    audiencePrefix: process.env.API_AUDIENCE_PREFIX,
    clientDetailsUrl: process.env.CLIENT_DETAILS_ENDPOINT,
    consentIdPrefix: process.env.CONSENT_ID_PREFIX,
    fido: {
        registration_options_endpoint: process.env.FIDO_REGISTRATION_OPTIONS,
        registration_endpoint: process.env.FIDO_REGISTRATION,
        sign_options: process.env.FIDO_SIGN_OPTIONS,
        sign: process.env.FIDO_SIGN
    }
};