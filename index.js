const express = require('express');
const app = express();
const morgan = require('morgan');
const cors = require('cors');
const path = require('path');
const rsa = require('rsa-scii-upc');
const bigconv = require('bigint-conversion');
const sha = require('object-sha');

const ___dirname = path.resolve();

global.puKey;
global.prKey;
global.Key = null;
global.iv = null;

async function claves() {
  const { publicKey, privateKey } = await rsa.generateRandomKeys(3072);

  puKey = publicKey;
  prKey = privateKey;

};


// settings
app.set('port', process.env.PORT || 8500);
app.set('json spaces', 2);

// middleware
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors());

// routes

// starting the server
app.listen(app.get('port'), () => {
  claves();
  console.log(`Server on port ${app.get('port')}`);
});

app.get('/test', (req, res) => {
  res.sendFile(path.join(___dirname + '/test.json'));
});

app.get('/key', (req, res) => {

  class PublicKey {
    constructor(e, n) {
      this.e = bigconv.bigintToHex(e);
      this.n = bigconv.bigintToHex(n);
    }
  }

  publicKey = new PublicKey(
    puKey.e,
    puKey.n
  )

  res.status(200).send(publicKey);

});


app.post("/mensaje3NoRepudio", async (req, res) => {

  clientePublicKey = new rsa.PublicKey(bigconv.hexToBigint(req.body.mensaje.e), bigconv.hexToBigint(req.body.mensaje.n));
  console.log(clientePublicKey);
  
  Key = req.body.mensaje.body.msg;
  iv = req.body.mensaje.body.iv;

  
  if ( await verifyHash(clientePublicKey) == true) {

    
    console.log(Key);
    console.log(iv);

    const body = {
      type: '4',
      src: 'A',
      ttp: "TTP",
      dst: 'B',
      msg: req.body.mensaje.body.msg,
      iv: req.body.mensaje.body.iv
    }

    const digest = await digestHash(body);

    const pkp = bigconv.bigintToHex(prKey.sign(bigconv.textToBigint(digest)));

    res.status(200).send({
      body, pkp
    });

  } else {
    res.status(400).send("No se ha podido verificar al cliente A");
  }

  async function digestHash(body){
    const d = await sha.digest(body, 'SHA-256');
    return d;
  }

  async function verifyHash(clientePublicKey) {
    const hashBody = await sha.digest(req.body.mensaje.body, 'SHA-256')

    var verify = false;

    if (hashBody == bigconv.bigintToText(clientePublicKey.verify(bigconv.hexToBigint(req.body.mensaje.pko)))) {
      verify = true
    }
    console.log(verify);

    return verify
  }

});

app.get("/SKeyType4", async (req, res) => {

    const body = {
      type: '4',
      src: 'A',
      ttp: "TTP",
      dst: 'B',
      msg: Key,
      iv: iv
    }

    const digest = await digestHash(body);

    const pkp = bigconv.bigintToHex(prKey.sign(bigconv.textToBigint(digest)));

    console.log(Key);

    res.status(200).send({
      body, pkp
    });

    Key = null;
    iv = null;


  async function digestHash(body){
    const d = await sha.digest(body, 'SHA-256');
    return d;
  }


});


