import dotenv from 'dotenv';
import fetch from 'node-fetch';
import * as pgp from 'openpgp';
import { inspect } from 'util';
import { v4 as uuid } from 'uuid';

dotenv.config();

const passboltDomain = process.env.PASSBOLT_DOMAIN!;
const userFingerprint = process.env.USER_FINGERPRINT!;
const privateKeyArmored = process.env.PRIVATE_KEY!;
const privateKeyPassphrase = process.env.PRIVATE_KEY_PASSPHRASE!;

const main = async () => {
  const response = await fetch(`${passboltDomain}/auth/verify.json`);
  const data = await response.json();

  const serverKey = data.body.keydata;
  const serverFingerprint = data.body.fingerprint;

  const token = `gpgauthv1.3.0|36|${uuid()}|gpgauthv1.3.0`;

  const encrypted = await pgp.encrypt({
    message: await pgp.createMessage({ text: token }),
    encryptionKeys: await pgp.readKey({ armoredKey: serverKey }),
  });

  const response2 = await fetch(`${passboltDomain}/auth/verify.json`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      gpg_auth: { keyid: userFingerprint, server_verify_token: encrypted },
    }),
  });

  const response3 = await fetch(`${passboltDomain}/auth/login.json`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ gpg_auth: { keyid: userFingerprint } }),
  });

  const encodedUserToken = response3.headers.get('x-gpgauth-user-auth-token')!;
  const userToken = decodeURIComponent(encodedUserToken).replace(/\\\+/g, ' ');

  const privateKey = await pgp.decryptKey({
    privateKey: await pgp.readPrivateKey({ armoredKey: privateKeyArmored }),
    passphrase: privateKeyPassphrase,
  });

  const decrypted = await pgp.decrypt({
    message: await pgp.readMessage({ armoredMessage: userToken }),
    decryptionKeys: privateKey,
  });

  console.log(decrypted);

  const response4 = await fetch(`${passboltDomain}/auth/login.json`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ gpg_auth: { keyid: userFingerprint, user_token_result: decrypted.data } }),
  });

  console.log(response4.headers);

  console.log(inspect(await response4.json(), false, 10, true));
};

main().catch(console.error);
