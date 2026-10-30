import { IDaaSCredentialProviderFactory } from '@cloud-idaas/core-sdk';
import { IDaaSPamClient } from '@cloud-idaas/pam-client-sdk';

async function main() {
  await IDaaSCredentialProviderFactory.init();
  try {
    const pam = new IDaaSPamClient();
    try {
      await pam.getApiKey(process.env.IDAAS_CREDENTIAL_IDENTIFIER || 'credential-id');
    } finally {
      pam.close();
    }
  } finally {
    await IDaaSCredentialProviderFactory.close();
  }
}
main().catch((error) => {
  console.error(error instanceof Error ? error.message : 'SDK call failed');
  process.exitCode = 1;
});
