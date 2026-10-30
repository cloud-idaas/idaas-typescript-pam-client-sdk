import {
  ConfigException,
  CredentialException,
  DefaultHttpClient,
  type HttpClient,
  type HttpConfiguration,
  type IDaaSCredentialProvider,
  IDaaSCredentialProviderFactory,
  isIDaaSException,
  IDaaSUnexpectedException,
  type Logger,
  PAM_SCOPE,
  endpointUrl,
  parseJson,
  record,
  required,
} from '@cloud-idaas/core-sdk';

export interface PamClientOptions {
  developerApiEndpoint?: string;
  idaasInstanceId?: string;
  credentialProvider?: IDaaSCredentialProvider;
  httpClient?: HttpClient;
  httpConfiguration?: HttpConfiguration;
  logger?: Logger;
}
export interface JwtContent {
  jwtValue: string;
  derivedShortToken?: string;
}
export interface AuthenticationToken {
  authenticationTokenId?: string;
  authenticationTokenType?: string;
  consumerId?: string;
  consumerType?: string;
  credentialProviderId?: string;
  revoked?: boolean;
  expirationTime?: number;
  instanceId?: string;
  createTime?: number;
  updateTime?: number;
  creatorId?: string;
  creatorType?: string;
}
export interface JwtTokenResponse extends AuthenticationToken {
  jwtContent: JwtContent;
}
export interface JwtGenerationOptions {
  issuer?: string;
  customClaims?: Record<string, unknown>;
  expiration?: number;
  includeDerivedShortToken?: boolean;
}
export interface TokenListOptions {
  nextToken?: string;
  maxResults?: number;
  revoked?: boolean;
  expired?: boolean;
}
export interface PageableResponse<T> {
  entities: T[];
  nextToken?: string;
  maxResults?: number;
  totalCount?: number;
}
/** Preserves wire fields; cloud SDK naming differences are handled at the adapter boundary. */
export interface CloudAccountRoleAccessCredential {
  accessCredentialExpiresAt?: number;
  alibabaCloudStsToken?: {
    accessKeyId?: string;
    accessKeySecret?: string;
    securityToken?: string;
    expiration?: string;
  };
  awsStsToken?: {
    accessKeyId?: string;
    secretAccessKey?: string;
    sessionToken?: string;
    expiration?: string;
  };
  tencentCloudStsToken?: {
    tmpSecretId?: string;
    tmpSecretKey?: string;
    token?: string;
    expiration?: string;
    expiredTime?: number;
  };
}
export function credentialString(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.trim())
    throw new CredentialException(`Response is missing ${field}`, 'InvalidCredentialResponse');
  return value;
}
function validateConfigurationObject(value: unknown): void {
  // Do not let Core's localized display labels determine PAM error classification.
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new ConfigException('configuration must be an object', 'InvalidResponse');
}
function jwtContent(value: unknown): JwtContent {
  const data = record(value, 'jwtContent');
  const jwtValue = credentialString(data.jwtValue, 'jwtValue');
  if (data.derivedShortToken !== undefined && typeof data.derivedShortToken !== 'string')
    throw new CredentialException(
      'derivedShortToken has an invalid type',
      'InvalidCredentialResponse',
    );
  return {
    jwtValue,
    ...(typeof data.derivedShortToken === 'string'
      ? { derivedShortToken: data.derivedShortToken }
      : {}),
  };
}
function authenticationToken(value: unknown): AuthenticationToken {
  const input = record(value, 'AuthenticationToken');
  const output: AuthenticationToken = {};
  for (const field of [
    'authenticationTokenId',
    'authenticationTokenType',
    'consumerId',
    'consumerType',
    'credentialProviderId',
    'instanceId',
    'creatorId',
    'creatorType',
  ] as const) {
    const item = input[field];
    if (item !== undefined) {
      if (typeof item !== 'string')
        throw new CredentialException(`${field} has an invalid type`, 'InvalidResponse');
      output[field] = item;
    }
  }
  for (const field of ['expirationTime', 'createTime', 'updateTime'] as const) {
    const item = input[field];
    if (item !== undefined) {
      if (typeof item !== 'number' || !Number.isFinite(item))
        throw new CredentialException(`${field} has an invalid type`, 'InvalidResponse');
      output[field] = item;
    }
  }
  if (input.revoked !== undefined) {
    if (typeof input.revoked !== 'boolean')
      throw new CredentialException('revoked has an invalid type', 'InvalidResponse');
    output.revoked = input.revoked;
  }
  return output;
}

/** Copies only validated public wire fields so arbitrary JSON cannot cross the type boundary. */
function cloudAccessCredential(value: unknown): CloudAccountRoleAccessCredential {
  const input = record(value, 'cloudAccountRoleAccessCredential');
  const result: CloudAccountRoleAccessCredential = {};
  if (input.accessCredentialExpiresAt !== undefined) {
    if (
      typeof input.accessCredentialExpiresAt !== 'number' ||
      !Number.isFinite(input.accessCredentialExpiresAt)
    )
      throw new CredentialException(
        'accessCredentialExpiresAt has an invalid type',
        'InvalidCredentialResponse',
      );
    result.accessCredentialExpiresAt = input.accessCredentialExpiresAt;
  }
  const fields = {
    alibabaCloudStsToken: ['accessKeyId', 'accessKeySecret', 'securityToken', 'expiration'],
    awsStsToken: ['accessKeyId', 'secretAccessKey', 'sessionToken', 'expiration'],
    tencentCloudStsToken: ['tmpSecretId', 'tmpSecretKey', 'token', 'expiration'],
  } as const;
  for (const name of Object.keys(fields) as (keyof typeof fields)[]) {
    if (input[name] === undefined) continue;
    const token = record(input[name], name);
    const parsed: Record<string, string> = {};
    for (const field of fields[name]) {
      if (token[field] !== undefined) parsed[field] = credentialString(token[field], field);
    }
    result[name] = parsed;
  }
  if (result.tencentCloudStsToken && input.tencentCloudStsToken !== undefined) {
    const token = record(input.tencentCloudStsToken, 'tencentCloudStsToken');
    if (token.expiredTime !== undefined) {
      if (typeof token.expiredTime !== 'number' || !Number.isFinite(token.expiredTime))
        throw new CredentialException(
          'expiredTime has an invalid type',
          'InvalidCredentialResponse',
        );
      result.tencentCloudStsToken.expiredTime = token.expiredTime;
    }
  }
  if (!result.alibabaCloudStsToken && !result.awsStsToken && !result.tencentCloudStsToken)
    throw new CredentialException(
      'Response is missing cloud credentials',
      'InvalidCredentialResponse',
    );
  return result;
}

/** Injected providers take precedence; only missing providers use the public default factory. */
export class IDaaSPamClient {
  private readonly endpoint: string;
  private readonly instanceId: string;
  private readonly provider: IDaaSCredentialProvider;
  private readonly http: HttpClient;
  private closed = false;
  /**
   * @param options - Injected endpoints, instance, and provider take precedence; only missing options use the default Core factory.
   * @throws ConfigException - Input is invalid or the required default factory is not initialized.
   * @remarks Construction does not request tokens; close releases owned HTTP resources and leaves injected resources caller-owned.
   */
  constructor(private readonly options: PamClientOptions = {}) {
    this.options = { ...options };
    const defaults =
      !options.developerApiEndpoint || !options.idaasInstanceId || !options.credentialProvider
        ? IDaaSCredentialProviderFactory.getConfig()
        : undefined;
    const endpoint = options.developerApiEndpoint || defaults?.developerApiEndpoint;
    required(endpoint, 'developerApiEndpoint');
    const instance = options.idaasInstanceId || defaults?.idaasInstanceId;
    required(instance, 'idaasInstanceId');
    this.endpoint = endpointUrl(endpoint).href.replace(/\/$/, '');
    this.instanceId = instance;
    this.provider = options.credentialProvider || {
      async getCredential() {
        return (
          await IDaaSCredentialProviderFactory.getIDaaSCredentialProvider(PAM_SCOPE)
        ).getCredential();
      },
      async getAccessToken() {
        return (
          await IDaaSCredentialProviderFactory.getIDaaSCredentialProvider(PAM_SCOPE)
        ).getAccessToken();
      },
    };
    if (typeof this.provider.getAccessToken !== 'function')
      throw new ConfigException(
        'credentialProvider is missing getAccessToken',
        'InvalidCredentialProvider',
      );
    this.http =
      options.httpClient ||
      new DefaultHttpClient(options.httpConfiguration || defaults?.httpConfiguration);
  }
  private async request(
    path: string,
    method: 'GET' | 'POST',
    body?: Record<string, unknown>,
    query?: Record<string, unknown>,
    authenticated = true,
  ): Promise<Record<string, unknown>> {
    if (this.closed) throw new ConfigException('PAM client is closed', 'Closed');
    try {
      const url = new URL(`${this.endpoint}/v2/${encodeURIComponent(this.instanceId)}${path}`);
      for (const [key, value] of Object.entries(query || {}))
        if (value !== undefined && value !== null) url.searchParams.set(key, String(value));
      const headers: Record<string, string> = {};
      if (authenticated) {
        const token = await this.provider.getAccessToken();
        required(token, 'accessToken');
        headers.authorization = `Bearer ${token}`;
      }
      if (body) headers['content-type'] = 'application/json';
      if (this.closed) throw new ConfigException('PAM client is closed', 'Closed');
      const response = await this.http.send({
        url: url.href,
        method,
        headers,
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      if (!response.body && response.statusCode >= 200 && response.statusCode < 300) return {};
      return record(parseJson(response));
    } catch (error) {
      if (isIDaaSException(error)) throw error;
      throw new IDaaSUnexpectedException(
        'PAM request failed; check the custom credential provider, HTTP implementation, or request data',
        'PamRequestFailed',
      );
    }
  }
  /**
   * @param credentialIdentifier - Server-side credential identifier.
   * @returns The API key; returns null and logs INFO for explicit server-side apiKeyContent=null.
   * @throws IDaaSException - Arguments, authentication, requests, or responses are invalid; other malformed responses never become null.
   */
  async getApiKey(credentialIdentifier: string): Promise<string | null> {
    required(credentialIdentifier, 'credentialIdentifier');
    const body = await this.request('/credentials/_/actions/obtain', 'GET', undefined, {
      credentialIdentifier,
    });
    const content = record(body.credentialContent);
    if (content.apiKeyContent === null) {
      // null is an explicit server result; missing fields and other invalid types still fail.
      try {
        if (this.options.logger)
          this.options.logger.info('pam_api_key', { status: 'not_available' });
        else console.info('pam_api_key', { status: 'not_available' });
      } catch {
        /* Log observers must not change the established result. */
      }
      return null;
    }
    return credentialString(record(content.apiKeyContent).apiKey, 'apiKey');
  }
  /**
   * Requests a server-generated JWT; this SDK does not sign JWTs locally.
   * @param credentialProviderIdentifier - JWT credential provider identifier.
   * @param subject - Token subject.
   * @param audiences - Nonempty collection of target audiences.
   * @param options - Optional claims, issuer, lifetime in seconds, and derived short-token flag.
   * @returns Server-side token description containing jwtContent.
   * @throws IDaaSException - Arguments, authentication, requests, or responses are invalid.
   */
  async generateJwtAuthenticationToken(
    credentialProviderIdentifier: string,
    subject: string,
    audiences: readonly string[],
    options: JwtGenerationOptions = {},
  ): Promise<JwtTokenResponse> {
    validateConfigurationObject(options);
    required(credentialProviderIdentifier, 'credentialProviderIdentifier');
    required(subject, 'subject');
    if (!Array.isArray(audiences) || !audiences.length)
      throw new ConfigException('audiences must not be empty', 'InvalidAudiences');
    for (const audience of audiences) required(audience, 'audience');
    if (options.issuer !== undefined) required(options.issuer, 'issuer');
    if (options.customClaims !== undefined) validateConfigurationObject(options.customClaims);
    if (
      options.includeDerivedShortToken !== undefined &&
      typeof options.includeDerivedShortToken !== 'boolean'
    )
      throw new ConfigException(
        'includeDerivedShortToken must be a boolean',
        'InvalidConfiguration',
      );
    if (
      options.expiration !== undefined &&
      (!Number.isInteger(options.expiration) || options.expiration <= 0)
    )
      throw new ConfigException(
        'expiration must be a positive integer in seconds',
        'InvalidExpiration',
      );
    const body = await this.request('/authenticationTokens/_/actions/generateJwt', 'POST', {
      ...options,
      credentialProviderIdentifier,
      subject,
      audiences,
    });
    return { ...authenticationToken(body), jwtContent: jwtContent(body.jwtContent) };
  }
  /**
   * @param consumerId - Consumer ID.
   * @param authenticationTokenId - Generated token ID.
   * @returns JWT and optional derived short token; request failures reject with SDK exceptions.
   */
  async obtainJwtAuthenticationToken(
    consumerId: string,
    authenticationTokenId: string,
  ): Promise<JwtContent> {
    required(consumerId, 'consumerId');
    required(authenticationTokenId, 'authenticationTokenId');
    return jwtContent(
      (
        await this.request('/authenticationTokens/_/actions/obtainJwt', 'POST', {
          consumerId,
          authenticationTokenId,
        })
      ).jwtContent,
    );
  }
  /**
   * @param derivedShortToken - Server-derived short token.
   * @returns JWT content; this endpoint neither retrieves nor sends a Bearer token.
   * @throws IDaaSException - Input, requests, or responses are invalid.
   */
  async obtainJwtAuthenticationTokenByDerivedShortToken(
    derivedShortToken: string,
  ): Promise<JwtContent> {
    required(derivedShortToken, 'derivedShortToken');
    return jwtContent(
      (
        await this.request(
          '/authenticationTokens/_/actions/obtainJwtByDerivedShortToken',
          'POST',
          { derivedShortToken },
          undefined,
          false,
        )
      ).jwtContent,
    );
  }
  /**
   * @param consumerId - Consumer ID.
   * @param credentialProviderIdentifier - Credential provider identifier.
   * @param options - Pagination and status filters; false values are preserved and omitted nextToken selects the first page.
   * @returns A page snapshot; omitted nextToken marks the end and raw null is normalized to undefined.
   * @throws IDaaSException - Input, authentication, requests, or responses are invalid.
   */
  async listAuthenticationTokens(
    consumerId: string,
    credentialProviderIdentifier: string,
    options: TokenListOptions = {},
  ): Promise<PageableResponse<AuthenticationToken>> {
    validateConfigurationObject(options);
    required(consumerId, 'consumerId');
    required(credentialProviderIdentifier, 'credentialProviderIdentifier');
    if (options.nextToken !== undefined && typeof options.nextToken !== 'string')
      throw new ConfigException('nextToken must be a string', 'InvalidPagination');
    for (const field of ['revoked', 'expired'] as const)
      if (options[field] !== undefined && typeof options[field] !== 'boolean')
        throw new ConfigException(`${field} must be a boolean`, 'InvalidConfiguration');
    if (
      options.maxResults !== undefined &&
      (!Number.isInteger(options.maxResults) || options.maxResults <= 0)
    )
      throw new ConfigException('maxResults must be a positive integer', 'InvalidPagination');
    const body = await this.request('/authenticationTokens', 'GET', undefined, {
      ...options,
      consumerId,
      credentialProviderIdentifier,
    });
    if (!Array.isArray(body.entities))
      throw new CredentialException('Paginated response is missing entities', 'InvalidResponse');
    const result: PageableResponse<AuthenticationToken> = {
      entities: body.entities.map(authenticationToken),
    };
    if (typeof body.nextToken === 'string') {
      if (body.nextToken) result.nextToken = body.nextToken;
    } else if (body.nextToken !== undefined && body.nextToken !== null) {
      throw new CredentialException('nextToken has an invalid type', 'InvalidResponse');
    }
    for (const field of ['maxResults', 'totalCount'] as const) {
      const value = body[field];
      if (value !== undefined) {
        if (typeof value !== 'number' || !Number.isInteger(value) || value < 0)
          throw new CredentialException(`${field} is invalid`, 'InvalidResponse');
        result[field] = value;
      }
    }
    return result;
  }
  /**
   * @param token - Token to validate.
   * @param tokenTypeHint - Optional server-side token type hint.
   * @returns The active status, including valid false; uses no Bearer authentication and rejects errors with SDK exceptions.
   */
  async validateAuthenticationToken(token: string, tokenTypeHint?: string): Promise<boolean> {
    required(token, 'token');
    if (tokenTypeHint !== undefined) required(tokenTypeHint, 'tokenTypeHint');
    const body = await this.request(
      '/authenticationTokens/_/actions/validate',
      'POST',
      { token, token_type_hint: tokenTypeHint },
      undefined,
      false,
    );
    if (typeof body.active !== 'boolean')
      throw new CredentialException('Response is missing active', 'InvalidResponse');
    return body.active;
  }
  /**
   * @param token - Token to revoke.
   * @param tokenTypeHint - Optional token type hint.
   * @throws IDaaSException - The request fails.
   */
  async revokeAuthenticationToken(token: string, tokenTypeHint?: string): Promise<void> {
    required(token, 'token');
    if (tokenTypeHint !== undefined) required(tokenTypeHint, 'tokenTypeHint');
    await this.request('/authenticationTokens/_/actions/revoke', 'POST', {
      token,
      token_type_hint: tokenTypeHint,
    });
  }
  /**
   * @param token - Token to reinstate.
   * @param tokenTypeHint - Optional token type hint.
   * @throws IDaaSException - The request fails.
   */
  async reinstateAuthenticationToken(token: string, tokenTypeHint?: string): Promise<void> {
    required(token, 'token');
    if (tokenTypeHint !== undefined) required(tokenTypeHint, 'tokenTypeHint');
    await this.request('/authenticationTokens/_/actions/reinstate', 'POST', {
      token,
      token_type_hint: tokenTypeHint,
    });
  }
  /**
   * @param consumerId - Consumer ID.
   * @param credentialProviderIdentifier - Credential provider identifier.
   * @returns Resolves when revocation completes; request failures reject with SDK exceptions.
   */
  async revokeAuthenticationTokenByConsumer(
    consumerId: string,
    credentialProviderIdentifier: string,
  ): Promise<void> {
    required(consumerId, 'consumerId');
    required(credentialProviderIdentifier, 'credentialProviderIdentifier');
    await this.request('/authenticationTokens/_/actions/revokeByConsumer', 'POST', {
      consumerId,
      credentialProviderIdentifier,
    });
  }
  /**
   * @param consumerId - Consumer ID.
   * @param credentialProviderIdentifier - Credential provider identifier.
   * @returns Resolves when reinstatement completes; request failures reject with SDK exceptions.
   */
  async reinstateAuthenticationTokenByConsumer(
    consumerId: string,
    credentialProviderIdentifier: string,
  ): Promise<void> {
    required(consumerId, 'consumerId');
    required(credentialProviderIdentifier, 'credentialProviderIdentifier');
    await this.request('/authenticationTokens/_/actions/reinstateByConsumer', 'POST', {
      consumerId,
      credentialProviderIdentifier,
    });
  }
  /**
   * @param roleExternalId - Cloud account role external ID.
   * @returns An independent validated wire response; parent expiration uses Unix seconds and cloud expiration uses an ISO string.
   * @throws IDaaSException - Input, authentication, requests, or responses are invalid; this method creates no STS cache.
   */
  async obtainAccessCredential(roleExternalId: string): Promise<CloudAccountRoleAccessCredential> {
    required(roleExternalId, 'roleExternalId');
    const body = await this.request(
      '/cloudAccountRoles/_/actions/obtainAccessCredential',
      'GET',
      undefined,
      { cloudAccountRoleExternalId: roleExternalId },
    );
    return cloudAccessCredential(body.cloudAccountRoleAccessCredential);
  }
  /** Idempotently releases owned HTTP resources, leaving injected providers, HTTP, and loggers open. */
  close(): void {
    this.closed = true;
    if (!this.options.httpClient && this.http instanceof DefaultHttpClient) this.http.close();
  }
  /** @returns A configuration builder without I/O; build and direct construction use the same validation. */
  static builder(): PamClientBuilder {
    return new PamClientBuilder();
  }
}
/** PAM configuration builder; built clients retain snapshots unaffected by later builder changes. */
export class PamClientBuilder {
  private readonly options: PamClientOptions = {};
  /**
   * @param value - HTTP(S) endpoint, defaulting to HTTPS when no scheme is provided.
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
   * @param value - Caller-owned PAM scope provider, taking precedence over the default factory.
   * @returns This builder.
   */
  credentialProvider(value: IDaaSCredentialProvider): this {
    this.options.credentialProvider = value;
    return this;
  }
  /**
   * @param value - Shared HTTP client with a caller-managed lifecycle.
   * @returns This builder.
   */
  httpClient(value: HttpClient): this {
    this.options.httpClient = value;
    return this;
  }
  /**
   * @returns A client that has not requested credentials.
   * @throws ConfigException - The configuration is invalid or the default factory is unavailable.
   */
  build(): IDaaSPamClient {
    return new IDaaSPamClient(this.options);
  }
}
