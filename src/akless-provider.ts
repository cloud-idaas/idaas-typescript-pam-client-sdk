import {
  CachedResultSupplier,
  type CacheOptions,
  CredentialException,
  type HttpClient,
  type IDaaSCredentialProvider,
  required,
} from '@cloud-idaas/core-sdk';
import {
  type CloudAccountRoleAccessCredential,
  IDaaSPamClient,
  type PamClientOptions,
} from './client';

/** Shared dynamic credential configuration for three clouds; injected resources remain caller-owned. */
export interface AklessProviderOptions extends PamClientOptions {
  /** Cloud account role external ID, mapped to the Developer API cloudAccountRoleExternalId query parameter. */
  roleExternalId: string;
  /** Optional shared PAM query source; provider close leaves it open. */
  pamClient?: Pick<IDaaSPamClient, 'obtainAccessCredential'>;
  /** Expiration mode, Unix-millisecond clock, jitter, and logger options; default LENIENT mode cannot extend actual expiration. */
  cache?: CacheOptions;
}
/** Shared expiration contract for cloud caches; adapters define their specific secret fields. */
export interface ExpiringCredential {
  /** ISO 8601 expiration with a time zone, explicitly converted to Unix milliseconds in the internal cache. */
  expiration: string;
}
/**
 * Fluent builder shared by cloud providers; configuration methods perform no I/O.
 * @remarks build passes independent configuration to the adapter constructor; injected resources remain caller-owned.
 */
export class AklessProviderBuilder<T> {
  private readonly options: Omit<AklessProviderOptions, 'roleExternalId'> & {
    roleExternalId?: string;
  } = {};
  /** @param create - Adapter constructor accepting complete role configuration; must not implicitly warm up during construction. */
  constructor(private readonly create: (options: AklessProviderOptions) => T) {}
  /**
   * @param value - Required role external ID, validated during build.
   * @returns This builder.
   */
  roleExternalId(value: string): this {
    this.options.roleExternalId = value;
    return this;
  }
  /**
   * @param value - Developer API base endpoint.
   * @returns This builder.
   */
  developerApiEndpoint(value: string): this {
    this.options.developerApiEndpoint = value;
    return this;
  }
  /**
   * @param value - IDaaS instance ID.
   * @returns This builder.
   */
  idaasInstanceId(value: string): this {
    this.options.idaasInstanceId = value;
    return this;
  }
  /**
   * @param value - Shared machine credential source taking precedence over the default factory; provider close leaves it open.
   * @returns This builder.
   */
  credentialProvider(value: IDaaSCredentialProvider): this {
    this.options.credentialProvider = value;
    return this;
  }
  /**
   * @param value - Caller-owned shared HTTP instance.
   * @returns This builder.
   */
  httpClient(value: HttpClient): this {
    this.options.httpClient = value;
    return this;
  }
  /**
   * @param value - Existing PAM query source; cleanup ownership is not transferred.
   * @returns This builder.
   */
  pamClient(value: Pick<IDaaSPamClient, 'obtainAccessCredential'>): this {
    this.options.pamClient = value;
    return this;
  }
  /**
   * @param value - Cache mode, millisecond clock, and observer configuration.
   * @returns This builder.
   */
  cacheOptions(value: CacheOptions): this {
    this.options.cache = value;
    return this;
  }
  /**
   * Creates an independent adapter instance that requests STS credentials only on first use.
   * @returns An adapter provider; callers must close its owned resources after use.
   * @throws ConfigException - The role is missing, adapter configuration is invalid, or the required default factory is not initialized.
   */
  build(): T {
    const roleExternalId = this.options.roleExternalId;
    required(roleExternalId, 'roleExternalId');
    return this.create({ ...this.options, roleExternalId });
  }
}
/**
 * Converts parent Unix seconds and cloud token ISO expiration to a conservative actual deadline.
 * @param parent - Developer API role credential response, with accessCredentialExpiresAt in Unix seconds.
 * @param tokenExpiration - Optional valid ISO 8601 timestamp with a time zone; dates without a time zone are rejected.
 * @returns Unix milliseconds, using the earlier deadline when both exist; never invents expiration from defaults.
 * @throws CredentialException - Any supplied timestamp is invalid, no valid expiration is provided, or credentials have expired.
 */
export function credentialExpiration(
  parent: CloudAccountRoleAccessCredential,
  tokenExpiration?: string,
): number {
  const values: number[] = [];
  if (parent.accessCredentialExpiresAt !== undefined) {
    if (
      typeof parent.accessCredentialExpiresAt !== 'number' ||
      !Number.isFinite(parent.accessCredentialExpiresAt)
    )
      throw new CredentialException('accessCredentialExpiresAt is invalid', 'InvalidExpiration');
    values.push(parent.accessCredentialExpiresAt * 1000);
  }
  if (tokenExpiration !== undefined) {
    // Date.parse also accepts years and dates without time zones and normalizes February 30; the wire contract rejects these.
    const parts =
      typeof tokenExpiration === 'string'
        ? /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-](\d{2}):(\d{2}))$/.exec(
            tokenExpiration,
          )
        : null;
    const year = Number(parts?.[1]);
    const month = Number(parts?.[2]);
    const day = Number(parts?.[3]);
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    const valid =
      parts &&
      month >= 1 &&
      month <= 12 &&
      day >= 1 &&
      day <= days[month - 1]! &&
      Number(parts[4]) < 24 &&
      Number(parts[5]) < 60 &&
      Number(parts[6]) < 60 &&
      (parts[7] === 'Z' || (Number(parts[8]) < 24 && Number(parts[9]) < 60));
    const value = valid ? Date.parse(tokenExpiration) : NaN;
    if (!Number.isFinite(value))
      throw new CredentialException('expiration is invalid', 'InvalidExpiration');
    values.push(value);
  }
  const expiration = values.length ? Math.min(...values) : NaN;
  if (!Number.isFinite(expiration) || expiration <= Date.now())
    throw new CredentialException(
      'Temporary credentials have expired or lack an expiration time',
      'InvalidExpiration',
    );
  return expiration;
}
/**
 * Shared role queries and access-triggered refresh for three clouds; adapters map cloud SDK fields.
 * @remarks Injected PAM, HTTP, and machine credential sources remain caller-owned. Without injected PAM, creates one
 * and releases owned resources on close. Instances and roles have independent caches, with no implicit shared state.
 */
export class CachedCloudCredentialProvider<T extends ExpiringCredential> {
  private readonly pam: Pick<IDaaSPamClient, 'obtainAccessCredential'>;
  private readonly cache: CachedResultSupplier<T>;
  private readonly now: () => number;
  private closed = false;
  /**
   * Creates a provider without requesting STS credentials.
   * @param options - Required role and injected sources, endpoints, and cache configuration.
   * @param parse - Validates and maps the wire response to a domain value with a valid ISO expiration timestamp.
   * @throws ConfigException - The configuration is invalid or the required default factory is not initialized.
   */
  constructor(
    private readonly options: AklessProviderOptions,
    parse: (value: CloudAccountRoleAccessCredential) => T,
  ) {
    this.options = { ...options };
    required(options.roleExternalId, 'roleExternalId');
    const roleExternalId = options.roleExternalId;
    this.pam = options.pamClient || new IDaaSPamClient(options);
    this.now = options.cache?.clock || Date.now;
    this.cache = new CachedResultSupplier(async () => {
      const value = parse(await this.pam.obtainAccessCredential(roleExternalId));
      return { value, expiresAt: Date.parse(value.expiration) };
    }, options.cache);
  }
  /**
   * Retrieves current role credentials, coalescing concurrent refreshes and enforcing actual expiration.
   * @returns An independent top-level snapshot; built-in cloud models contain only string fields.
   * @throws IDaaSException - Query or parsing fails without usable cached credentials, strict refresh fails, credentials have expired, or the provider is closed.
   */
  async getCredentials(): Promise<T> {
    const value = await this.cache.get();
    this.assertAvailable(value);
    return { ...value };
  }
  /**
   * Rechecks credential delivery after the final await in derived adapters.
   * @param value - Credentials with an ISO expiration timestamp or an equivalent converted deadline.
   * @throws CredentialException - The provider is closed, the clock is invalid, or credentials have expired.
   */
  protected assertAvailable(value: ExpiringCredential): void {
    // Expiration or closure may occur before this continuation resumes; recheck synchronously before delivery.
    if (this.closed) throw new CredentialException('Credential provider is closed', 'Closed');
    const now = this.now();
    if (!Number.isFinite(now))
      throw new CredentialException('Cache clock is invalid', 'InvalidClock');
    const expiresAt = Date.parse(value.expiration);
    if (!Number.isFinite(expiresAt) || expiresAt <= now)
      throw new CredentialException(
        'Temporary credentials have reached their actual expiration time',
        'InvalidExpiration',
      );
  }
  /**
   * Idempotently closes the cache and owned PAM client; subsequent reads fail and in-flight results are not stored.
   * @remarks Leaves caller-injected PAM, HTTP, and machine credential sources open.
   */
  close(): void {
    this.closed = true;
    this.cache.close();
    if (!this.options.pamClient && this.pam instanceof IDaaSPamClient) this.pam.close();
  }
}
