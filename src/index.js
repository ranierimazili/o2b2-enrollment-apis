import express from 'express';
import https from 'https';
import routes from './routes.js';
import config from './config.js';
import * as selfsigned from 'selfsigned';

const app = express();
const port = config.serverPort;

//Gera certificados auto-assinados
const attrs = [{ name: 'commonName', value: config.host }];
const hostCerts = selfsigned.generate(attrs, { days: 3650, keySize: 2048 });

const options = {
    key: hostCerts.private,
    cert: hostCerts.cert,
    requestCert: true,
    rejectUnauthorized: false
};

app.use(express.text({type: "application/jwt"}));
app.use(express.urlencoded({ extended: true }));
app.use('/open-banking', routes);

const server = https.createServer(options, app);

server.listen(port, () => {
    console.log(`Server listening at https://${config.host}:${port}`);
});