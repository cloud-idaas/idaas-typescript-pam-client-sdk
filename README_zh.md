# IDaaS TypeScript PAM Client SDK

简体中文 | [English](README.md)

通过 IDaaS PAM 获取 API Key、JWT 和云角色凭证，并管理令牌生命周期。

## 环境与安装

支持 Node.js 20、22、24，JavaScript CommonJS/ESM 以及 TypeScript 4.7 及以上版本。本 SDK 用于 Node.js，不用于浏览器。请以 npm registry 中的实际可用版本为准；评估尚未发布的版本时，使用提供的安装包归档。

```sh
npm install @cloud-idaas/core-sdk @cloud-idaas/pam-client-sdk
```

## 使用

通过 CLOUD_IDAAS_CONFIG_PATH 或 ~/.cloud_idaas/client-config.json 配置 Core，提供 developerApiEndpoint 及已获 PAM 访问授权的身份，并替换示例标识。 将以下 ESM 示例保存为 `example.mjs`，通过 Node.js 运行。CommonJS 使用相同的具名导出和 `require`，异步调用放在 async 函数中。

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

## 支持的操作

客户端支持获取 API Key、获取和生成 JWT、短令牌交换、令牌查询与校验，以及吊销和恢复操作，也支持按消费方处理令牌。`obtainAccessCredential` 用于获取云角色凭证。

`getApiKey()` 返回 `string | null`，请显式处理没有可用密钥的情况。请求失败或响应无效时抛出 SDK 异常。不支持 `fetchOAuthAuthenticationToken` 及已废弃的 PAM OAuth 流程；Core 认证不受影响。

使用具有 PAM 访问权限的 Core 提供者。默认提供者申请 `urn:cloud:idaas:pam|.all`，显式传入的提供者优先。`httpConfiguration.userAgent` 可定制 IDaaS 请求标识。

所有请求完成后调用 `close()`；注入的共享提供者和 HTTP 客户端由调用方管理。不要打印返回的凭证或将其写入示例配置。

## 示例与支持

[examples](examples) 提供 CommonJS、ESM 和 TypeScript 示例。问题反馈请使用 [GitHub Issues](https://github.com/cloud-idaas/idaas-typescript-pam-client-sdk/issues)，开发说明见源码仓库的[贡献指南](https://github.com/cloud-idaas/idaas-typescript-pam-client-sdk/blob/master/CONTRIBUTING.md)。

## 许可证

[Apache License 2.0](LICENSE)。
