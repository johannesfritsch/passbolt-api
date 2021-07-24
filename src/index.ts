import fetch from "node-fetch";
import { v4 as uuid } from "uuid";
import * as pgp from "openpgp";
import FormData from "form-data";

const main = async () => {
  const response = await fetch(
    `https://pw.liquidi.team/auth/verify.json`
  );
  const data = await response.json();

  const serverKey = data.body.keydata;
  const serverFingerprint = data.body.fingerprint;

  const token = `gpgauthv1.3.0|36|${uuid()}|gpgauthv1.3.0`;

  const encrypted = await pgp.encrypt({
    message: await pgp.createMessage({ text: token }),
    encryptionKeys: await pgp.readKey({ armoredKey: `-----BEGIN PGP PUBLIC KEY BLOCK-----
    Version: OpenPGP.js v4.10.9
    Comment: https://openpgpjs.org
    
    xsBNBGD37sUBCACi234aA1twJLnaA/BcW1jQ6NpE5G/VWcVYapxfkvGxZ4Np
    ot8j06TICSfJJl7TZHUBdT0USUj70Cnsg2jUQfL4v5sD5FgykBCIxMHfCDaD
    26Fub6Ch8Qmh/Q8zshG92X1XDSsyqUgvpnqBQFVIqTvWdr01vh0sC/Jsl+fP
    THETg/MhYgywf2jWu49/3fj6YWsR01zT3gPEU16PMaPjUZ6lH/IUmoEycJai
    zXY1Ic32GpZQ1RY+J/r0zQTdpgYKY//eHrHia+2Ys7CxUUiStZBTfjsPEeII
    ekEvtZFrcVxv/cCKRelU19bN3cK0h2CoxRr9h5KuDQDu0f5E+FbRfBObABEB
    AAHNKEpvaGFubmVzIEZyaXRzY2ggPGpvaGFubmVzQGxpcXVpZGkudGVhbT7C
    wI0EEAEIACAFAmD37sUGCwkHCAMCBBUICgIEFgIBAAIZAQIbAwIeAQAhCRBn
    cb5LiYtm4xYhBC0L7ZbLJZglxU+4xWdxvkuJi2bj+3EH/RBHxYcZqYmZbjUB
    PQVpfFV6alBlXlXYvKCDNXDe57wsoqYhkka+5E5UMWxqFeXNQVKSHjuDufVZ
    wePbPEt6gJJ2LpyPvqF6goImCYySJlG9saZDvEwwWqBv65ay5KvyvwU7r7Ic
    qCkLDJbLfw24ouNrvGYuLPIV487OOGr2CpwR9Z46CFnW4dX5XTUBPu4X7Dnr
    4wxWaRLXU4q0lm0NtsrbDxwZT20XD4wudtbHUfNaezwrrIWDVoEBOu0aw8j8
    brCKofIKd3v9201Ium7BmBytfoVRe72Sb3RE3xHZ/jFL3pGHiK6+091VAlQu
    wz0Xl7+urUyzxbY0H5bJsDDbNGDOwE0EYPfuxQEIAKkNXhSw/oQ5qGJvWRdk
    6g7kSRFv/tLYD98HRTHzLGX5FNtI05/om99lAtqe+d5HcmTZw/Y87uQcFbl5
    z4zG3ZI0b1nk6qJb6H3ie6amFImtbGRj0o5MgXxgnuaqf4rHwIL0IEE0ElOg
    njVJq0/qLo+D7IwXEROhqDUgVjiTaYAxdHtaBCyFIxXWP+EVOzoB42RkxHDf
    FL5OQRcMsN4fw0S50iDvdrHwtWqUjKJswJUD8ZDrqjm814Tiwaqaz94+SgQ2
    Zhp7WeWBD5E+mSCSbBylo3OVlE8xZE/dnNrhtHUXrePlbQMDzwobqRClXeCh
    8s8LlrqZJ93bzjSzbGNbPaEAEQEAAcLAdgQYAQgACQUCYPfuxQIbDAAhCRBn
    cb5LiYtm4xYhBC0L7ZbLJZglxU+4xWdxvkuJi2bjQC4H/iqR7E5vr2SVjo5B
    z59nR6+9w0Jpfw8h9Jv4sTaftLZaI426FxU7SgMdOCfn+JaXCZSDMoOywy4Z
    RTRoy8kpInPo2f8t/XHCgHe+au9W7YHtYt8D5pJX6AjVduV5deiMHAyCRmS7
    mcoGi8mx5WT0dJYEUugoiwmHxMbmHOb87C3et/aVvPIkC1qGDCOUovYSGncU
    l9WCJdm3HWv1woh2N16XXch9risoO5OqIO+qxoqbSL5p4uqb+ubk/2DrPwMO
    Al7Nx79icdjTHShgOvre1RdjoFqf2jVRst3ed8uTOtH4C0PABsl46zh17UaU
    uwyXPxpc4xIwR/If1rdD+7rjnMs=
    =EMan
    -----END PGP PUBLIC KEY BLOCK-----
    ` }),
  });

  const response2 = await fetch(
    `https://pw.liquidi.team/auth/verify.json`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        gpg_auth: {
          keyid: '2D0BED96CB259825C54FB8C56771BE4B898B66E3',
          server_verify_token: encrypted,
        },
      }),
    }
  );

  console.log(await response2.text());
};

main();
