const crypto = require('crypto'),
  fs = require("fs"),
  https = require("https");

const privateKey = fs.readFileSync('rootCAKey.pem').toString();
const certificate = fs.readFileSync('rootCACert.pem').toString();

const options = {
    key: privateKey,
    cert: certificate
  };

const handler = function (req, res) {
    console.log(req.headers);
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end('Hello World\n');
};

const server = https.createServer(options);
server.addListener("request", handler);
server.listen(8000);
