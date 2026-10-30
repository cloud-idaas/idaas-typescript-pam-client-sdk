import { strict as assert } from 'node:assert';
import { IDaaSUnexpectedException } from '@cloud-idaas/core-sdk';
import { CachedCloudCredentialProvider, credentialExpiration, IDaaSPamClient } from '../src';

const provider = {
  async getAccessToken() {
    return 'bearer';
  },
  async getCredential() {
    return {
      accessToken: 'bearer',
      tokenType: 'Bearer',
      expiresIn: 100,
      expiresAt: Date.now() / 1000 + 100,
    };
  },
};
function client(
  body: unknown,
  logger?: { info(): void; warn(): void; error(): void },
): IDaaSPamClient {
  return new IDaaSPamClient({
    developerApiEndpoint: 'https://pam.example',
    idaasInstanceId: 'i',
    credentialProvider: provider,
    logger,
    httpClient: {
      async send() {
        return { statusCode: 200, headers: {}, body: JSON.stringify(body) };
      },
    },
  });
}

describe('Tencent Cloud STS Unix-second expiration', () => {
  it('preserves numeric expiredTime in public responses and rejects invalid types', async () => {
    for (const value of [1234567890, '1234567890', null]) {
      const pam = client({
        cloudAccountRoleAccessCredential: { tencentCloudStsToken: { expiredTime: value } },
      });
      try {
        if (typeof value === 'number') {
          assert.equal(
            (await pam.obtainAccessCredential('role')).tencentCloudStsToken?.expiredTime,
            value,
          );
        } else {
          await assert.rejects(pam.obtainAccessCredential('role'));
        }
      } finally {
        pam.close();
      }
    }
  });
});

describe('Review regression: PAM behavior and error contracts', () => {
  it('TS-TYPE-02 validates JavaScript status and claims options before sending requests', async () => {
    const pam = client({});
    try {
      await assert.rejects(
        pam.listAuthenticationTokens('consumer', 'provider', JSON.parse('{"revoked":"false"}')),
        { name: 'ConfigException' },
      );
      await assert.rejects(
        pam.generateJwtAuthenticationToken(
          'provider',
          'subject',
          ['aud'],
          JSON.parse('{"customClaims":[]}'),
        ),
        { name: 'ConfigException' },
      );
      await assert.rejects(
        pam.generateJwtAuthenticationToken(
          'provider',
          'subject',
          ['aud'],
          JSON.parse('{"includeDerivedShortToken":"false"}'),
        ),
        { name: 'ConfigException' },
      );
    } finally {
      pam.close();
    }
  });
  it('F-PAM-CRED-01 returns null and logs INFO only for explicit apiKeyContent=null', async () => {
    let logs = 0;
    const pam = client(
      { credentialContent: { apiKeyContent: null } },
      {
        info() {
          logs++;
        },
        warn() {},
        error() {},
      },
    );
    try {
      assert.equal(await pam.getApiKey('id'), null);
      assert.equal(logs, 1);
    } finally {
      pam.close();
    }
    for (const content of [{}, { apiKeyContent: 'invalid' }, { apiKeyContent: {} }]) {
      const malformed = client({ credentialContent: content });
      try {
        await assert.rejects(malformed.getApiKey('id'));
      } finally {
        malformed.close();
      }
    }
  });
  it('TS-ERR-01/02 sanitizes injected provider failures without sending PAM requests', async () => {
    let requests = 0;
    const pam = new IDaaSPamClient({
      developerApiEndpoint: 'https://pam.example',
      idaasInstanceId: 'i',
      credentialProvider: {
        ...provider,
        async getAccessToken() {
          throw new Error('SECRET_VALUE');
        },
      },
      httpClient: {
        async send() {
          requests++;
          throw new Error('unreachable');
        },
      },
    });
    try {
      await assert.rejects(pam.getApiKey('id'), (error: unknown) => {
        assert(error instanceof IDaaSUnexpectedException);
        assert(!String(error).includes('SECRET_VALUE'));
        assert(!JSON.stringify(error).includes('SECRET_VALUE'));
        return true;
      });
      assert.equal(requests, 0);
    } finally {
      pam.close();
    }
  });
  it('TS-TYPE-02 validates public nested STS response types instead of asserting malformed JSON', async () => {
    for (const credential of [
      { accessCredentialExpiresAt: '2050', awsStsToken: {} },
      { awsStsToken: 123 },
      { awsStsToken: { accessKeyId: 123 } },
      {},
    ]) {
      const pam = client({ cloudAccountRoleAccessCredential: credential });
      try {
        await assert.rejects(pam.obtainAccessCredential('role'));
      } finally {
        pam.close();
      }
    }
  });
  it('F-LANG-07 preserves injected HTTP ownership and sends no request if closed while awaiting the provider', async () => {
    let release: (token: string) => void = () => undefined;
    let requests = 0;
    let closes = 0;
    const shared = {
      async send() {
        requests++;
        return { statusCode: 200, headers: {}, body: '{}' };
      },
      close() {
        closes++;
      },
    };
    const pam = new IDaaSPamClient({
      developerApiEndpoint: 'https://pam.example',
      idaasInstanceId: 'i',
      credentialProvider: {
        ...provider,
        getAccessToken: () =>
          new Promise<string>((resolve) => {
            release = resolve;
          }),
      },
      httpClient: shared,
    });
    const pending = pam.getApiKey('id');
    pam.close();
    release('bearer');
    await assert.rejects(pending, { errorCode: 'Closed' });
    assert.equal(requests, 0);
    assert.equal(closes, 0);
  });
});

describe('Review regression: cloud ISO 8601 expiration fields', () => {
  for (const transition of ['expire', 'close'] as const) {
    it(`TS-ASYNC-05 rejects STS delivery after ${transition} while awaiting cached credentials`, async () => {
      let now = Date.now();
      const expiresAt = now + 3600000;
      let armed = false;
      const source = new CachedCloudCredentialProvider(
        {
          roleExternalId: 'role',
          pamClient: {
            async obtainAccessCredential() {
              return {};
            },
          },
          cache: {
            clock: () => {
              if (armed)
                queueMicrotask(() => {
                  if (transition === 'close') source.close();
                  else now = expiresAt;
                });
              return now;
            },
            logger: { info() {}, warn() {}, error() {} },
          },
        },
        () => ({ expiration: new Date(expiresAt).toISOString() }),
      );
      try {
        await source.getCredentials();
        armed = true;
        await assert.rejects(source.getCredentials(), {
          errorCode: transition === 'close' ? 'Closed' : 'InvalidExpiration',
        });
      } finally {
        source.close();
      }
    });
  }
  it('rejects bare years, missing time zones, normalized invalid dates, and invalid time zones', () => {
    for (const value of [
      '2050',
      '2050-01-01',
      '2050-01-01T00:00:00',
      '2050-02-30T00:00:00Z',
      '2050-01-01T24:00:00Z',
      '2050-01-01T00:00:00+25:00',
    ])
      assert.throws(() => credentialExpiration({}, value), { errorCode: 'InvalidExpiration' });
    assert.equal(
      credentialExpiration({}, '2050-01-01T08:00:00+08:00'),
      Date.parse('2050-01-01T00:00:00Z'),
    );
    assert.equal(
      credentialExpiration({}, '2052-02-29T00:00:00Z'),
      Date.parse('2052-02-29T00:00:00Z'),
    );
  });
});
