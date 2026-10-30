# IDaaS TypeScript PAM Client SDK

[Simplified Chinese](README_zh.md) | English

Access API keys, JWT credentials, token lifecycle operations, and cloud role credentials through IDaaS PAM.

## Requirements and installation

Supports Node.js 20, 22, and 24, JavaScript CommonJS/ESM, and TypeScript 4.7 or later. This is a Node.js SDK, not a browser SDK. Check your registry for available beta versions; use a provided package archive when evaluating an unreleased version.

```sh
npm install @cloud-idaas/core-sdk @cloud-idaas/pam-client-sdk
```

## Usage

Configure Core using CLOUD_IDAAS_CONFIG_PATH or ~/.cloud_idaas/client-config.json. Provide developerApiEndpoint and an identity authorized for PAM access. Replace example identifiers with your settings. Save the following ESM example as `example.mjs` and run it with Node.js. CommonJS uses the same named exports through `require`; asynchronous calls belong inside an async function.

```javascript
import { IDaaSCredentialProviderFactory } from '@cloud-idaas/core-sdk';
import { IDaaSPamClient } from '@cloud-idaas/pam-client-sdk';

await IDaaSCredentialProviderFactory.init();
try {
  const provider = await IDaaSCredentialProviderFactory.getIDaaSCredentialProvider(
    'urn:cloud:idaas:pam|.all',
  );
  const pam = new IDaaSPamClient({
    developerApiEndpoint: 'https://developer-api.example.com',
    idaasInstanceId: 'instance-id',
    credentialProvider: provider,
  });
  try {
    const apiKey = await pam.getApiKey('credential-identifier');
    if (apiKey === null) {
      // Handle the server's explicit "API key unavailable" result.
    } else {
      // Use apiKey with the intended service; never print credentials.
    }
  } finally {
    pam.close();
  }
} finally {
  await IDaaSCredentialProviderFactory.close();
}
```

## Supported operations

The client supports API key retrieval, JWT retrieval/generation, short-token exchange, token listing/validation, and revoke/reinstate operations, including operations by consumer. `obtainAccessCredential` obtains cloud role credentials.

`getApiKey()` returns `string | null`; handle a missing key explicitly. Failed requests and invalid responses raise SDK errors. `fetchOAuthAuthenticationToken` and the deprecated PAM OAuth flows are not supported; Core authentication remains available.

Use an authorized Core provider for PAM access. The default provider requests `urn:cloud:idaas:pam|.all`; an explicitly supplied provider takes precedence. `httpConfiguration.userAgent` customizes IDaaS request identification.

Call `close()` after all requests finish. Injected shared providers and HTTP clients remain caller-owned. Never print or persist returned credentials in example configuration.

## Examples and support

See [examples](examples) for CommonJS, ESM, and TypeScript samples. Report issues through [GitHub Issues](https://github.com/cloud-idaas/idaas-typescript-pam-client-sdk/issues). Development instructions are in the repository's [contribution guide](https://github.com/cloud-idaas/idaas-typescript-pam-client-sdk/blob/master/CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE).
