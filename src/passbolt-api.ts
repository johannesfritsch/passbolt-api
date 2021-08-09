import fetch, { Headers } from 'node-fetch';
import * as pgp from 'openpgp';
import { Cookie, CookieJar } from 'tough-cookie';
import { v4 as uuid } from 'uuid';
import { Group } from './types/group';
import { Resource } from './types/resource';
import { ResourceType } from './types/resource-type';
import { User } from './types/user';

interface UserAuth {
  fingerprint: string;
  privateKeyArmored: string;
  publicKeyArmored: string;
  privateKeyPassphrase: string;
}

interface PassboltResource {
  name: string;
  username?: string;
  description?: string;
  uri?: string;
  plainPassword?: string;
  secretMessage(): string;
  serialize(): Record<string, string | undefined>;
}

export class PassboltPassword implements PassboltResource {
  constructor(
    public name: string,
    public plainPassword: string,
    public username?: string,
    public description?: string,
    public uri?: string,
  ) {}

  secretMessage(): string {
    return this.plainPassword;
  }

  serialize() {
    return { name: this.name, username: this.username, description: this.description, uri: this.uri };
  }
}

export class PassboltSecureNote implements PassboltResource {
  constructor(
    public name: string,
    public description: string,
    public plainPassword?: string,
    public username?: string,
    public uri?: string,
  ) {}

  secretMessage(): string {
    return JSON.stringify({ password: this.plainPassword || 'no-password', description: this.description });
  }

  serialize() {
    return { name: this.name, username: this.username, uri: this.uri };
  }
}

export class PassboltApi {
  private token: string;
  private resourceTypeIds: { simplePassword: string; withDescription: string } | undefined;
  private cookieJar = new CookieJar();

  constructor(private baseUrl: string, private userAuth: UserAuth) {
    this.token = `gpgauthv1.3.0|36|${uuid()}|gpgauthv1.3.0`;
  }

  private async request(
    url: string,
    method = 'GET',
    body: Record<string, any> = {},
    headers: Record<string, string> = {},
  ) {
    const csrfToken = this.cookieJar.getCookiesSync(this.baseUrl).find((c) => c.key === 'csrfToken')?.value;

    const response = await fetch(`${this.baseUrl}${url}`, {
      method,
      headers: {
        ...headers,
        cookie: this.cookieJar.getCookieStringSync(this.baseUrl),
        ...(csrfToken && Object.keys(body).length > 0 ? { 'X-CSRF-Token': csrfToken } : {}),
        'Content-Type': 'application/json',
      },
      body: Object.keys(body).length > 0 ? JSON.stringify(body) : undefined,
    });

    if (response.ok) return { headers: response.headers, body: await response.json() };

    const text = await response.text();

    try {
      throw JSON.parse(text);
    } catch (error) {
      throw text;
    }
  }

  private storeCookies(headers: Headers) {
    const cookies = headers.raw()['set-cookie'].map((c) => Cookie.parse(c)!);
    cookies.forEach((c) => this.cookieJar.setCookieSync(c, this.baseUrl));
  }

  public async verifyServer() {
    const { headers, body } = await this.request('/auth/verify.json');
    this.storeCookies(headers);

    const serverKey = body.body.keydata;

    const encrypted = await pgp.encrypt({
      message: await pgp.createMessage({ text: this.token }),
      encryptionKeys: await pgp.readKey({ armoredKey: serverKey }),
    });

    const { headers: verifiedHeaders } = await this.request('/auth/verify.json', 'POST', {
      gpg_auth: { keyid: this.userAuth.fingerprint, server_verify_token: encrypted },
    });

    const serverToken = verifiedHeaders.get('x-gpgauth-verify-response');

    if (serverToken !== this.token) throw new Error('invalid token received from server');
  }

  public async login() {
    const { headers } = await this.request('/auth/login.json', 'POST', {
      gpg_auth: { keyid: this.userAuth.fingerprint },
    });

    const encodedUserToken = headers.get('x-gpgauth-user-auth-token')!;
    const userToken = decodeURIComponent(encodedUserToken).replace(/\\\+/g, ' ');

    const privateKey = await pgp.decryptKey({
      privateKey: await pgp.readPrivateKey({ armoredKey: this.userAuth.privateKeyArmored }),
      passphrase: this.userAuth.privateKeyPassphrase,
    });

    const decrypted = await pgp.decrypt({
      message: await pgp.readMessage({ armoredMessage: userToken }),
      decryptionKeys: privateKey,
    });

    const { headers: loginHeaders } = await this.request('/auth/login.json', 'POST', {
      gpg_auth: { keyid: this.userAuth.fingerprint, user_token_result: decrypted.data },
    });
    this.storeCookies(loginHeaders);
  }

  public async listResourceTypes(): Promise<ResourceType[]> {
    const { body } = await this.request('/resource-types.json');
    return body.body;
  }

  public async fetchResourceTypeIds() {
    const resourceTypes = await this.listResourceTypes();
    const passwordType = resourceTypes.find((type) => type.slug === 'password-string');
    if (!passwordType) throw new Error('No resource type with slug password-string found');
    const withDescriptionType = resourceTypes.find((type) => type.slug === 'password-and-description');
    if (!withDescriptionType) throw new Error('No resource type with slug password-and-description found');
    this.resourceTypeIds = { simplePassword: passwordType.id, withDescription: withDescriptionType.id };
  }

  private async getResourceTypeId(resource: PassboltResource) {
    if (!this.resourceTypeIds) await this.fetchResourceTypeIds();
    if (resource instanceof PassboltPassword) return this.resourceTypeIds!.simplePassword;
    if (resource instanceof PassboltSecureNote) return this.resourceTypeIds!.withDescription;
  }

  public async createResource(resource: PassboltResource): Promise<Resource> {
    const encrypted = await pgp.encrypt({
      message: await pgp.createMessage({ text: resource.secretMessage() }),
      encryptionKeys: await pgp.readKey({ armoredKey: this.userAuth.publicKeyArmored }),
    });

    const { body } = await this.request('/resources.json', 'POST', {
      ...resource.serialize(),
      resource_type_id: await this.getResourceTypeId(resource),
      secrets: [{ data: encrypted }],
    });
    return body.body;
  }

  public async createGroup(name: string, users: { user_id: string; is_admin?: boolean }[]): Promise<Group> {
    const { body } = await this.request('/groups.json', 'POST', { name, groups_users: users });
    return body.body;
  }

  public async listUsers(inGroup?: string): Promise<User[]> {
    const { body } = await this.request(
      `/users.json?api-version=v2${inGroup ? `&filter[has-groups]=${inGroup}` : ''}`,
      'GET',
    );
    return body.body;
  }

  public async shareWithGroup(resourceId: string, resource: PassboltResource, groupId: string) {
    const members = (await this.listUsers(groupId)).filter((user) => user.gpgkey);

    await this.request(`/share/resource/${resourceId}.json`, 'PUT', {
      permissions: [
        {
          aro: 'Group',
          aro_foreign_key: groupId,
          aco: 'Resource',
          aco_foreign_key: resourceId,
          type: 15, // owner
        },
      ],
      secrets: await Promise.all(
        members.map(async (user) => ({
          user_id: user.id,
          data: await pgp.encrypt({
            message: await pgp.createMessage({ text: resource.secretMessage() }),
            encryptionKeys: await pgp.readKey({ armoredKey: user.gpgkey!.armored_key }),
          }),
        })),
      ),
    });
  }
}
