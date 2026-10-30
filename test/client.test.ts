import { strict as assert } from 'node:assert';
import {
  ClientException,
  type HttpClient,
  type HttpRequest,
  ServerException,
} from '@cloud-idaas/core-sdk';
import { IDaaSPamClient, credentialExpiration } from '../src';

// Request paths and fields follow @alicloud/eiam-developerapi20220225@1.9.0.
describe('PAM Developer API contract', () => {
  const requests: HttpRequest[] = [];
  let bearerReads = 0;
  const provider = {
    async getCredential() {
      return {
        accessToken: 'bearer',
        tokenType: 'Bearer',
        expiresIn: 3600,
        expiresAt: Date.now() / 1000 + 3600,
      };
    },
    async getAccessToken() {
      bearerReads++;
      return 'bearer';
    },
  };
  function client(): IDaaSPamClient {
    const http: HttpClient = {
      async send(request) {
        requests.push(request);
        const path = new URL(request.url).pathname;
        const body = path.endsWith('/obtain')
          ? { credentialContent: { apiKeyContent: { apiKey: 'api-key' } } }
          : /\/(generateJwt|obtainJwt|obtainJwtByDerivedShortToken)$/.test(path)
            ? {
                authenticationTokenId: 'id',
                jwtContent: { jwtValue: 'jwt', derivedShortToken: 'short' },
              }
            : path.endsWith('/authenticationTokens')
              ? {
                  entities: [{ authenticationTokenId: 'id', revoked: false }],
                  nextToken: 'next',
                  totalCount: 1,
                  maxResults: 2,
                }
              : path.endsWith('/validate')
                ? { active: false }
                : path.endsWith('/obtainAccessCredential')
                  ? {
                      cloudAccountRoleAccessCredential: {
                        accessCredentialExpiresAt: Date.now() / 1000 + 3600,
                        awsStsToken: { accessKeyId: 'ak' },
                      },
                    }
                  : {};
        return { statusCode: 200, headers: {}, body: JSON.stringify(body) };
      },
    };
    return IDaaSPamClient.builder()
      .developerApiEndpoint('https://pam.example')
      .idaasInstanceId('instance/one')
      .credentialProvider(provider)
      .httpClient(http)
      .build();
  }
  beforeEach(() => {
    requests.length = 0;
    bearerReads = 0;
  });
  it('treats nextToken=null as the end of pagination rather than invalid credentials', async () => {
    const pam = new IDaaSPamClient({
      developerApiEndpoint: 'https://pam.example',
      idaasInstanceId: 'i',
      credentialProvider: provider,
      httpClient: {
        async send() {
          return { statusCode: 200, headers: {}, body: '{"entities":[],"nextToken":null}' };
        },
      },
    });
    assert.deepEqual(await pam.listAuthenticationTokens('consumer', 'provider'), { entities: [] });
    pam.close();
  });
  it('uses injected providers without the default factory and retrieves API keys by identifier with Bearer authentication', async () => {
    const pam = client();
    assert.equal(await pam.getApiKey('credential +/'), 'api-key');
    assert.equal(
      new URL(requests[0]!.url).pathname,
      '/v2/instance%2Fone/credentials/_/actions/obtain',
    );
    assert.equal(
      new URL(requests[0]!.url).searchParams.get('credentialIdentifier'),
      'credential +/',
    );
    assert.equal(requests.length, 1);
    assert.equal(requests[0]!.headers?.authorization, 'Bearer bearer');
    assert.equal(bearerReads, 1);
    pam.close();
  });
  it('generates and retrieves JWTs, including short-token exchange, through server APIs', async () => {
    const pam = client();
    const generated = await pam.generateJwtAuthenticationToken('provider', 'subject', ['aud'], {
      includeDerivedShortToken: false,
      customClaims: { tenant: 'one' },
    });
    assert.equal(generated.authenticationTokenId, 'id');
    assert.equal(generated.jwtContent.jwtValue, 'jwt');
    assert.equal(JSON.parse(requests[0]!.body!).includeDerivedShortToken, false);
    assert.equal((await pam.obtainJwtAuthenticationToken('consumer', 'id')).jwtValue, 'jwt');
    assert.equal(
      (await pam.obtainJwtAuthenticationTokenByDerivedShortToken('short')).jwtValue,
      'jwt',
    );
    assert.equal(requests[2]!.headers?.authorization, undefined);
    assert.equal(bearerReads, 2);
    pam.close();
  });
  it('preserves false pagination filters, skips Bearer retrieval for validation, and accepts active=false', async () => {
    const pam = client();
    const page = await pam.listAuthenticationTokens('consumer', 'provider', {
      revoked: false,
      expired: false,
      maxResults: 2,
    });
    assert.equal(page.entities[0]!.revoked, false);
    assert.equal(new URL(requests[0]!.url).searchParams.get('revoked'), 'false');
    assert.equal(await pam.validateAuthenticationToken('token', 'jwt'), false);
    assert.equal(requests[1]!.headers?.authorization, undefined);
    assert.deepEqual(JSON.parse(requests[1]!.body!), { token: 'token', token_type_hint: 'jwt' });
    assert.equal(bearerReads, 1);
    pam.close();
  });
  it('supports revocation and reinstatement for individual tokens and consumers', async () => {
    const pam = client();
    await pam.revokeAuthenticationToken('token', 'jwt');
    await pam.reinstateAuthenticationToken('token');
    await pam.revokeAuthenticationTokenByConsumer('consumer', 'provider');
    await pam.reinstateAuthenticationTokenByConsumer('consumer', 'provider');
    assert.deepEqual(
      requests.map((r) => new URL(r.url).pathname.split('/').pop()),
      ['revoke', 'reinstate', 'revokeByConsumer', 'reinstateByConsumer'],
    );
    assert.deepEqual(JSON.parse(requests[2]!.body!), {
      consumerId: 'consumer',
      credentialProviderIdentifier: 'provider',
    });
    pam.close();
  });
  it('uses the correct role query and rejects new requests after closure', async () => {
    const pam = client();
    await pam.obtainAccessCredential('arn:role/a+b');
    assert.equal(
      new URL(requests[0]!.url).searchParams.get('cloudAccountRoleExternalId'),
      'arn:role/a+b',
    );
    pam.close();
    await assert.rejects(pam.getApiKey('id'));
  });
  it('distinguishes client and server errors without exposing raw credentials', async () => {
    for (const status of [403, 503]) {
      const pam = new IDaaSPamClient({
        developerApiEndpoint: 'https://pam.example',
        idaasInstanceId: 'i',
        credentialProvider: provider,
        httpClient: {
          async send() {
            return {
              statusCode: status,
              headers: {},
              body: '{"error_code":"Denied","error_description":"sensitive-token"}',
            };
          },
        },
      });
      await assert.rejects(pam.getApiKey('id'), (error: unknown) => {
        assert(
          status === 403 ? error instanceof ClientException : error instanceof ServerException,
        );
        assert(!String(error).includes('sensitive-token'));
        return true;
      });
      pam.close();
    }
  });
});

describe('Shared cloud expiration rules', () => {
  it('uses the earlier deadline when parent Unix seconds and token ISO expiration both exist', () => {
    const early = Math.floor(Date.now() / 1000) + 1000;
    assert.equal(
      credentialExpiration(
        { accessCredentialExpiresAt: early },
        new Date((early + 100) * 1000).toISOString(),
      ),
      early * 1000,
    );
    assert.throws(() => credentialExpiration({}, 'bad-date'));
    assert.throws(() => credentialExpiration({ accessCredentialExpiresAt: 1 }));
  });
});
