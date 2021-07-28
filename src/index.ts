import dotenv from 'dotenv';
import fetch from 'node-fetch';
import * as pgp from 'openpgp';
import { Cookie, CookieJar } from 'tough-cookie';
import { v4 as uuid } from 'uuid';

dotenv.config();

const passboltDomain = process.env.PASSBOLT_DOMAIN!;
const userFingerprint = process.env.USER_FINGERPRINT!;
const privateKeyArmored = process.env.PRIVATE_KEY!;
const publicKeyArmored = process.env.PUBLIC_KEY!;
const privateKeyPassphrase = process.env.PRIVATE_KEY_PASSPHRASE!;

const cookieUrl = passboltDomain;
const cookieJar = new CookieJar();

const verifyServer = async (token: string) => {
  const response = await fetch(`${passboltDomain}/auth/verify.json`);
  const data = await response.json();

  const cookies = response.headers.raw()['set-cookie'].map((c) => Cookie.parse(c)!);
  cookies.forEach((c) => cookieJar.setCookieSync(c, cookieUrl));

  const serverKey = data.body.keydata;

  const encrypted = await pgp.encrypt({
    message: await pgp.createMessage({ text: token }),
    encryptionKeys: await pgp.readKey({ armoredKey: serverKey }),
  });

  const verifyResponse = await fetch(`${passboltDomain}/auth/verify.json`, {
    method: 'POST',
    headers: { cookie: cookieJar.getCookieStringSync(cookieUrl), 'Content-Type': 'application/json' },
    body: JSON.stringify({
      gpg_auth: { keyid: userFingerprint, server_verify_token: encrypted },
    }),
  });

  const serverToken = verifyResponse.headers.get('x-gpgauth-verify-response');

  if (serverToken !== token) throw new Error('invalid token received from server');
};

const login = async () => {
  const response = await fetch(`${passboltDomain}/auth/login.json`, {
    method: 'POST',
    headers: { cookie: cookieJar.getCookieStringSync(cookieUrl), 'Content-Type': 'application/json' },
    body: JSON.stringify({ gpg_auth: { keyid: userFingerprint } }),
  });

  const encodedUserToken = response.headers.get('x-gpgauth-user-auth-token')!;
  const userToken = decodeURIComponent(encodedUserToken).replace(/\\\+/g, ' ');

  const privateKey = await pgp.decryptKey({
    privateKey: await pgp.readPrivateKey({ armoredKey: privateKeyArmored }),
    passphrase: privateKeyPassphrase,
  });

  const decrypted = await pgp.decrypt({
    message: await pgp.readMessage({ armoredMessage: userToken }),
    decryptionKeys: privateKey,
  });

  const loginResponse = await fetch(`${passboltDomain}/auth/login.json`, {
    method: 'POST',
    headers: { cookie: cookieJar.getCookieStringSync(cookieUrl), 'Content-Type': 'application/json' },
    body: JSON.stringify({ gpg_auth: { keyid: userFingerprint, user_token_result: decrypted.data } }),
  });

  if (!loginResponse.ok) throw await response.json();

  const authenticatedCookies = loginResponse.headers.raw()['set-cookie'].map((c) => Cookie.parse(c)!);
  authenticatedCookies.forEach((c) => cookieJar.setCookieSync(c, cookieUrl));
};

const createPassword = async () => {
  const resourceTypeId = '669f8c64-242a-59fb-92fc-81f660975fd3';

  const encrypted = await pgp.encrypt({
    message: await pgp.createMessage({ text: 'test-password' }),
    encryptionKeys: await pgp.readKey({ armoredKey: publicKeyArmored }),
  });

  const response = await fetch(`${passboltDomain}/resources.json`, {
    method: 'POST',
    headers: {
      cookie: cookieJar.getCookieStringSync(cookieUrl),
      'X-CSRF-Token': cookieJar.getCookiesSync(cookieUrl).find((c) => c.key === 'csrfToken')!.value,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      name: 'API Test',
      description: 'API Test',
      username: 'test',
      resource_type_id: resourceTypeId,
      secrets: [{ data: encrypted }],
    }),
  });
  const data = await response.json();
  console.log(response.status, response.headers, data);
};

const main = async () => {
  const token = `gpgauthv1.3.0|36|${uuid()}|gpgauthv1.3.0`;
  await verifyServer(token);
  await login();

  await createPassword();
};

main().catch(console.error);
