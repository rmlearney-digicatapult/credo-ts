import { AgentContext } from '../../agent'
import { injectable } from '../../plugins'
import { zParseWithErrorHandling } from '../../utils/zod'
import { KeyManagementError } from './error/KeyManagementError'
import { KeyManagementKeyMismatchError } from './error/KeyManagementKeyMismatchError'
import { KeyManagementKeyNotFoundError } from './error/KeyManagementKeyNotFoundError'
import {
  asymmetricPublicJwkMatches,
  getJwkHumanDescription,
  type KmsJwkPrivate,
  type KmsJwkPublic,
  type KnownJwaSignatureAlgorithm,
  KnownJwaSignatureAlgorithms,
  keyAllowsDecrypt,
  keyAllowsDerive,
  keyAllowsEncrypt,
  keyAllowsSign,
  keyAllowsVerify,
  PublicJwk,
  supportedKeyDerivationAlgsForKey,
  supportedSigningAlgsForKey,
} from './jwk'
import { createKeyTypeForSigningAlgorithm } from './jwk/alg/signing'
import { KeyManagementModuleConfig } from './KeyManagementModuleConfig'
import type { KeyManagementService } from './KeyManagementService'
import {
  getKmsOperationHumanDescription,
  type KmsCapabilityOperation,
  type KmsDecryptOptions,
  type KmsDeleteKeyOptions,
  type KmsGetPublicKeyOptions,
  type KmsImportKeyOptions,
  type KmsOperation,
  type KmsRandomBytesOptions,
} from './options'
import { type WithBackend, type WithCreateKeyBackend, zWithBackend, zWithCreateKeyBackend } from './options/backend'
import {
  type KmsCreateKeyForSignatureAlgorithmOptions,
  type KmsCreateKeyOptions,
  type KmsCreateKeyReturn,
  type KmsCreateKeyType,
  type KmsCreateKeyTypeAsymmetric,
  zKmsCreateKeyForSignatureAlgorithmOptions,
  zKmsCreateKeyOptions,
} from './options/KmsCreateKeyOptions'
import { zKmsDecryptOptions } from './options/KmsDecryptOptions'
import { zKmsDeleteKeyOptions } from './options/KmsDeleteKeyOptions'
import {
  ecdhContentEncryptionAlgorithmsFor,
  type KmsEncryptOptions,
  zKmsEncryptOptions,
} from './options/KmsEncryptOptions'
import { zKmsGetPublicKeyOptions } from './options/KmsGetPublicKeyOptions'
import { type KmsImportKeyReturn, zKmsImportKeyOptions } from './options/KmsImportKeyOptions'
import { zKmsRandomBytesOptions } from './options/KmsRandomBytesOptions'
import { type KmsSignOptions, zKmsSignOptions } from './options/KmsSignOptions'
import { type KmsVerifyOptions, zKmsVerifyOptions } from './options/KmsVerifyOptions'

export type KmsKeyReference =
  | { keyId: string }
  | { publicJwk: PublicJwk; kmsKeyId?: string; allowLegacyKeyId?: boolean }

export interface ResolvedKmsKey {
  readonly keyId: string
  readonly backend: string
  readonly jwk: KmsJwkPublic
  readonly publicJwk?: PublicJwk
  readonly source: 'explicit' | 'kmsKeyId' | 'legacy'
}

export interface KmsSigningSelection extends ResolvedKmsKey {
  readonly algorithm: KnownJwaSignatureAlgorithm
}

export type KmsCanPerformResult =
  | { supported: true; backend: string; key?: ResolvedKmsKey }
  | {
      supported: false
      reason:
        | 'key-not-found'
        | 'key-mismatch'
        | 'backend-unsupported-request'
        | 'incompatible-key-algorithm'
        | 'incompatible-key-type'
        | 'disallowed-key-usage'
      message: string
      keyId?: string
      backend?: string
    }

type KmsKeyIdCandidate = Pick<ResolvedKmsKey, 'keyId' | 'source'>

type KmsCanPerformArguments =
  | [
      operation: Extract<KmsCapabilityOperation, { operation: 'sign' | 'decrypt' }>,
      key: KmsKeyReference | ResolvedKmsKey,
    ]
  | [
      operation: Extract<KmsCapabilityOperation, { operation: 'verify' | 'encrypt' }>,
      key?: KmsKeyReference | ResolvedKmsKey,
    ]

@injectable()
export class KeyManagementApi<Backends extends KeyManagementService[] = KeyManagementService[]> {
  public constructor(
    private keyManagementConfig: KeyManagementModuleConfig,
    private agentContext: AgentContext
  ) {}

  /**
   * Whether an operation is supported.
   *
   * @returns a list of backends that support the operation. In case
   * no backends are supported it returns an empty array
   */
  public supportedBackendsForOperation(operation: KmsOperation): string[] {
    // Backends report what they can compute, the ECDH content encryption rules live in the encrypt and decrypt schemas
    if ((operation.operation === 'encrypt' || operation.operation === 'decrypt') && operation.keyAgreement) {
      const encryption = operation.operation === 'encrypt' ? operation.encryption : operation.decryption
      const ecdhEncryptionAlgorithms = ecdhContentEncryptionAlgorithmsFor(operation.keyAgreement.algorithm)
      if (ecdhEncryptionAlgorithms && !ecdhEncryptionAlgorithms.includes(encryption.algorithm)) return []
    }

    const supportedBackends: string[] = []

    for (const kms of this.keyManagementConfig.backends) {
      const isOperationSupported = kms.isOperationSupported(this.agentContext, operation)
      if (isOperationSupported) {
        supportedBackends.push(kms.backend)
      }
    }

    return supportedBackends
  }

  /**
   * The JWA signature algorithms that at least one backend can sign with.
   *
   * Symmetric (HMAC) algorithms are excluded by default, since in most cases signatures are
   * verified by another party using a public key.
   */
  public supportedJwaSignatureAlgorithms(options?: {
    includeSymmetricAlgorithms?: boolean
    operation?: 'sign' | 'verify'
  }): KnownJwaSignatureAlgorithm[] {
    const includeSymmetricAlgorithms = options?.includeSymmetricAlgorithms ?? false
    // Preserve signing-only behavior for existing consumers during the consumer migration.
    const operation = options?.operation ?? 'sign'

    return Object.values(KnownJwaSignatureAlgorithms).filter(
      (algorithm) =>
        (includeSymmetricAlgorithms || createKeyTypeForSigningAlgorithm(algorithm).kty !== 'oct') &&
        this.supportedBackendsForOperation({ operation, algorithm }).length > 0
    )
  }

  /**
   * Resolve a key reference to public metadata without exposing private key material.
   */
  public async resolveKey(reference: KmsKeyReference): Promise<ResolvedKmsKey> {
    const candidates = this.keyIdCandidates(reference)

    for (const candidate of candidates) {
      let keyMismatch: KeyManagementKeyMismatchError | undefined
      for (const kms of this.keyManagementConfig.backends) {
        try {
          const key = await this.resolveKeyOnBackend(kms, candidate, reference)
          if (key) {
            if (candidate.source === 'legacy') {
              this.agentContext.config.logger.warn(
                `Resolved key '${candidate.keyId}' using a legacy key id. Migrate the key to an explicit KMS key id.`
              )
            }
            return key
          }
        } catch (error) {
          if (!(error instanceof KeyManagementKeyMismatchError)) throw error
          keyMismatch ??= error
        }
      }
      if (keyMismatch) throw keyMismatch
    }

    const keyId = candidates[0]?.keyId ?? 'unknown'
    throw new KeyManagementKeyNotFoundError(
      keyId,
      this.keyManagementConfig.backends.map((backend) => backend.backend)
    )
  }

  public async canPerform(...args: KmsCanPerformArguments): Promise<KmsCanPerformResult> {
    const [operation, key] = args
    if (!key && (operation.operation === 'sign' || operation.operation === 'decrypt')) {
      return {
        supported: false,
        reason: 'key-not-found',
        message: `A key is required for the '${operation.operation}' operation`,
      }
    }

    if (!key) {
      const supportedBackends = this.supportedBackendsForOperation(operation)
      if (this.keyManagementConfig.backends.length > 0) {
        const defaultBackend = this.keyManagementConfig.defaultBackend
        if (supportedBackends.includes(defaultBackend.backend)) {
          return { supported: true, backend: defaultBackend.backend }
        }
      }

      const firstCapableBackend = this.keyManagementConfig.backends.find((backend) =>
        supportedBackends.includes(backend.backend)
      )
      if (firstCapableBackend) {
        return { supported: true, backend: firstCapableBackend.backend }
      }

      return {
        supported: false,
        reason: 'backend-unsupported-request',
        message: `No key management service backend supports ${getKmsOperationHumanDescription(operation)}`,
      }
    }

    if (isResolvedKmsKey(key)) {
      const kms = this.keyManagementConfig.backends.find((backend) => backend.backend === key.backend)
      if (!kms?.isOperationSupported(this.agentContext, operation)) {
        return {
          supported: false,
          reason: 'backend-unsupported-request',
          message: `Backend '${key.backend}' does not support ${getKmsOperationHumanDescription(operation)}`,
          keyId: key.keyId,
          backend: key.backend,
        }
      }

      return this.checkResolvedKeyCapability(operation, key)
    }

    const candidates = this.keyIdCandidates(key)
    let keyMismatch: { error: KeyManagementKeyMismatchError; keyId: string; backend: string } | undefined
    const resolvedKeys = new Map<
      KeyManagementService,
      Map<string, ResolvedKmsKey | null | KeyManagementKeyMismatchError>
    >()
    const resolveKeyOnce = async (
      kms: KeyManagementService,
      candidate: KmsKeyIdCandidate
    ): Promise<ResolvedKmsKey | undefined> => {
      let backendKeys = resolvedKeys.get(kms)
      if (!backendKeys) {
        backendKeys = new Map()
        resolvedKeys.set(kms, backendKeys)
      }

      if (!backendKeys.has(candidate.keyId)) {
        try {
          backendKeys.set(candidate.keyId, (await this.resolveKeyOnBackend(kms, candidate, key)) ?? null)
        } catch (error) {
          if (!(error instanceof KeyManagementKeyMismatchError)) throw error
          backendKeys.set(candidate.keyId, error)
        }
      }

      const resolvedKey = backendKeys.get(candidate.keyId)
      if (resolvedKey instanceof KeyManagementKeyMismatchError) throw resolvedKey
      return resolvedKey ?? undefined
    }

    for (const kms of this.keyManagementConfig.backends) {
      if (!kms.isOperationSupported(this.agentContext, operation)) continue

      for (const candidate of candidates) {
        let resolvedKey: ResolvedKmsKey | undefined
        try {
          resolvedKey = await resolveKeyOnce(kms, candidate)
        } catch (error) {
          if (!(error instanceof KeyManagementKeyMismatchError)) throw error
          keyMismatch ??= { error, keyId: candidate.keyId, backend: kms.backend }
          continue
        }
        if (!resolvedKey) continue

        if (candidate.source === 'legacy') {
          this.agentContext.config.logger.warn(
            `Resolved key '${candidate.keyId}' using a legacy key id. Migrate the key to an explicit KMS key id.`
          )
        }
        return this.checkResolvedKeyCapability(operation, resolvedKey)
      }
    }

    for (const candidate of candidates) {
      for (const kms of this.keyManagementConfig.backends) {
        try {
          const resolvedKey = await resolveKeyOnce(kms, candidate)
          if (resolvedKey) {
            return {
              supported: false,
              reason: 'backend-unsupported-request',
              message: `The key exists in backend '${kms.backend}', but it does not support ${getKmsOperationHumanDescription(operation)}`,
              keyId: candidate.keyId,
              backend: kms.backend,
            }
          }
        } catch (error) {
          if (!(error instanceof KeyManagementKeyMismatchError)) throw error
          keyMismatch ??= { error, keyId: candidate.keyId, backend: kms.backend }
        }
      }
    }

    if (keyMismatch) {
      return {
        supported: false,
        reason: 'key-mismatch',
        message: keyMismatch.error.message,
        keyId: keyMismatch.keyId,
        backend: keyMismatch.backend,
      }
    }

    const keyId = candidates[0]?.keyId ?? 'unknown'
    return {
      supported: false,
      reason: 'key-not-found',
      message: `Key with key id '${keyId}' was not found in any configured backend`,
      keyId,
    }
  }

  private keyIdCandidates(reference: KmsKeyReference): KmsKeyIdCandidate[] {
    if ('keyId' in reference) return [{ keyId: reference.keyId, source: 'explicit' }]

    const candidates: KmsKeyIdCandidate[] = []
    if (reference.kmsKeyId) candidates.push({ keyId: reference.kmsKeyId, source: 'kmsKeyId' })

    const allowLegacyKeyId = reference.allowLegacyKeyId ?? true
    if (allowLegacyKeyId && reference.publicJwk.kty !== 'RSA') {
      const legacyKeyId = reference.publicJwk.legacyKeyId
      if (!candidates.some((candidate) => candidate.keyId === legacyKeyId)) {
        candidates.push({ keyId: legacyKeyId, source: 'legacy' })
      }
    }

    return candidates
  }

  private async resolveKeyOnBackend(
    kms: KeyManagementService,
    candidate: KmsKeyIdCandidate,
    reference: KmsKeyReference
  ): Promise<ResolvedKmsKey | undefined> {
    const jwk = await kms.getPublicKey(this.agentContext, candidate.keyId)
    if (!jwk) return undefined

    const referencePublicJwk = 'publicJwk' in reference ? reference.publicJwk.toJson() : undefined
    if (referencePublicJwk) {
      if (jwk.kty === 'oct' || !asymmetricPublicJwkMatches(jwk, referencePublicJwk)) {
        throw new KeyManagementKeyMismatchError(candidate.keyId)
      }
    }

    return {
      keyId: candidate.keyId,
      backend: kms.backend,
      jwk,
      publicJwk: jwk.kty === 'oct' ? undefined : PublicJwk.fromPublicJwk(jwk),
      source: candidate.source,
    }
  }

  private checkResolvedKeyCapability(operation: KmsCapabilityOperation, key: ResolvedKmsKey): KmsCanPerformResult {
    const { jwk } = key
    let allowedUsage: boolean
    if ((operation.operation === 'encrypt' || operation.operation === 'decrypt') && operation.keyAgreement) {
      allowedUsage = keyAllowsDerive(jwk)
    } else if (operation.operation === 'sign') {
      allowedUsage = keyAllowsSign(jwk)
    } else if (operation.operation === 'verify') {
      allowedUsage = keyAllowsVerify(jwk)
    } else if (operation.operation === 'encrypt') {
      allowedUsage = keyAllowsEncrypt(jwk)
    } else {
      allowedUsage = keyAllowsDecrypt(jwk)
    }

    if (!allowedUsage) {
      return {
        supported: false,
        reason: 'disallowed-key-usage',
        message: `Key '${key.keyId}' usage does not allow the '${operation.operation}' operation`,
        keyId: key.keyId,
        backend: key.backend,
      }
    }

    if (operation.operation === 'sign' || operation.operation === 'verify') {
      let supportedAlgorithms: boolean
      if (jwk.kty === 'oct') {
        supportedAlgorithms = operation.algorithm.startsWith('HS') && (!jwk.alg || jwk.alg === operation.algorithm)
      } else {
        supportedAlgorithms =
          supportedSigningAlgsForKey(jwk).includes(operation.algorithm) && (!jwk.alg || jwk.alg === operation.algorithm)
      }
      if (!supportedAlgorithms) {
        return {
          supported: false,
          reason: 'incompatible-key-algorithm',
          message: `Key '${key.keyId}' is not compatible with signature algorithm '${operation.algorithm}'`,
          keyId: key.keyId,
          backend: key.backend,
        }
      }
    }

    if (operation.operation === 'encrypt' || operation.operation === 'decrypt') {
      if (operation.keyAgreement) {
        const jwkSupportsAgreement =
          jwk.kty !== 'oct' && supportedKeyDerivationAlgsForKey(jwk).includes(operation.keyAgreement.algorithm)
        if (!jwkSupportsAgreement || (jwk.alg && jwk.alg !== operation.keyAgreement.algorithm)) {
          return {
            supported: false,
            reason: 'incompatible-key-algorithm',
            message: `Key '${key.keyId}' is not compatible with key agreement algorithm '${operation.keyAgreement.algorithm}'`,
            keyId: key.keyId,
            backend: key.backend,
          }
        }
      } else {
        let algorithm: string
        if (operation.operation === 'encrypt') {
          algorithm = operation.encryption.algorithm
        } else {
          algorithm = operation.decryption.algorithm
        }
        if (jwk.kty !== 'oct') {
          return {
            supported: false,
            reason: 'incompatible-key-type',
            message: `Key '${key.keyId}' must be symmetric for direct ${operation.operation}`,
            keyId: key.keyId,
            backend: key.backend,
          }
        }
        if (jwk.alg && jwk.alg !== algorithm) {
          return {
            supported: false,
            reason: 'incompatible-key-algorithm',
            message: `Key '${key.keyId}' is not compatible with encryption algorithm '${algorithm}'`,
            keyId: key.keyId,
            backend: key.backend,
          }
        }
      }
    }

    return { supported: true, backend: key.backend, key }
  }

  /**
   * Select the first candidate signing algorithm supported by the backend holding the key.
   */
  public async selectSignatureAlgorithm(options: {
    key: KmsKeyReference | ResolvedKmsKey
    candidates?: KnownJwaSignatureAlgorithm[]
  }): Promise<KmsSigningSelection> {
    const key = isResolvedKmsKey(options.key) ? options.key : await this.resolveKey(options.key)
    const compatibleAlgorithms =
      key.jwk.kty === 'oct'
        ? (Object.values(KnownJwaSignatureAlgorithms).filter((algorithm) =>
            algorithm.startsWith('HS')
          ) as KnownJwaSignatureAlgorithm[])
        : supportedSigningAlgsForKey(key.jwk)
    const candidates = options.candidates ?? compatibleAlgorithms

    for (const algorithm of candidates) {
      if (!compatibleAlgorithms.includes(algorithm) || (key.jwk.alg && key.jwk.alg !== algorithm)) continue

      const result = await this.canPerform({ operation: 'sign', algorithm }, key)
      if (result.supported) return { ...key, algorithm }
    }

    throw new KeyManagementError(
      `No candidate signing algorithm is supported by backend '${key.backend}' for ${getJwkHumanDescription(key.jwk)}`
    )
  }

  /**
   * Create a key.
   */
  public async createKey<Type extends KmsCreateKeyType>(
    options: WithCreateKeyBackend<KmsCreateKeyOptions<Type>, Backends>
  ): Promise<KmsCreateKeyReturn<Type>> {
    const { backend, ...kmsOptions } = zParseWithErrorHandling(
      zWithCreateKeyBackend(zKmsCreateKeyOptions),
      options,
      'Invalid options provided to createKey method'
    )

    const kms = this.getKms(this.agentContext, backend, {
      operation: 'createKey',
      type: options.type,
    })

    const key = await kms.createKey(this.agentContext, kmsOptions)
    key.publicJwk.kid = key.keyId

    this.agentContext.config.logger.debug(
      `Created key ${getJwkHumanDescription(key.publicJwk)} with key id '${key.keyId}'`
    )

    return key
  }

  /**
   * Create a key.
   */
  public async createKeyForSignatureAlgorithm(
    options: WithCreateKeyBackend<KmsCreateKeyForSignatureAlgorithmOptions, Backends>
  ): Promise<KmsCreateKeyReturn<KmsCreateKeyTypeAsymmetric>> {
    const { backend, algorithm, ...kmsOptions } = zParseWithErrorHandling(
      zWithCreateKeyBackend(zKmsCreateKeyForSignatureAlgorithmOptions),
      options,
      'Invalid options provided to createKeyForSignatureAlgorithm method'
    )

    const type = createKeyTypeForSigningAlgorithm(algorithm)
    const kms = this.getKms(this.agentContext, backend, {
      operation: 'createKey',
      type,
    })

    // Ensure the kid is set to the keyId
    const key = await kms.createKey(this.agentContext, {
      ...kmsOptions,
      type,
    })
    key.publicJwk.kid = key.keyId

    return key
  }

  /**
   * Sign using a key.
   */
  public async sign(options: WithBackend<KmsSignOptions, Backends>) {
    const { backend, ...kmsOptions } = zParseWithErrorHandling(
      zWithBackend(zKmsSignOptions),
      options,
      'Invalid options provided to sign method'
    )

    const operation = {
      operation: 'sign',
      algorithm: options.algorithm,
      keyId: options.keyId,
    } as const

    const kms = backend
      ? this.getKms(this.agentContext, backend, operation)
      : await this.getKmsForKeyOperation(options.keyId, operation)
    return await kms.sign(this.agentContext, kmsOptions)
  }

  /**
   * Verify using a key.
   */
  public async verify(options: WithBackend<KmsVerifyOptions, Backends>) {
    const { backend, ...kmsOptions } = zParseWithErrorHandling(
      zWithBackend(zKmsVerifyOptions),
      options,
      'Invalid options provided to verify method'
    )

    const keyId = options.key.keyId
    const operation = { operation: 'verify', algorithm: options.algorithm, keyId } as const
    const kms =
      backend || !keyId
        ? this.getKms(this.agentContext, backend, operation)
        : await this.getKmsForKeyOperation(keyId, operation)

    return await kms.verify(this.agentContext, kmsOptions)
  }

  /**
   * Encrypt.
   */
  public async encrypt(options: WithBackend<KmsEncryptOptions, Backends>) {
    const { backend, ...kmsOptions } = zParseWithErrorHandling(
      zWithBackend(zKmsEncryptOptions),
      options,
      'Invalid options provided to encrypt method'
    )

    const keyId = routingKeyId(kmsOptions.key)
    const operation = {
      operation: 'encrypt',
      encryption: options.encryption,
      keyAgreement: options.key.keyAgreement,
      keyId,
    } as const
    const kms =
      backend || !keyId
        ? this.getKms(this.agentContext, backend, operation)
        : await this.getKmsForKeyOperation(keyId, operation)

    return await kms.encrypt(this.agentContext, kmsOptions)
  }

  /**
   * Decrypt.
   */
  public async decrypt(options: WithBackend<KmsDecryptOptions, Backends>) {
    const { backend, ...kmsOptions } = zParseWithErrorHandling(
      zWithBackend(zKmsDecryptOptions),
      options,
      'Invalid options provided to decrypt method'
    )

    const keyId = routingKeyId(options.key)
    const operation = {
      operation: 'decrypt',
      decryption: options.decryption,
      keyAgreement: options.key.keyAgreement,
      keyId,
    } as const
    const kms =
      backend || !keyId
        ? this.getKms(this.agentContext, backend, operation)
        : await this.getKmsForKeyOperation(keyId, operation)

    return await kms.decrypt(this.agentContext, kmsOptions)
  }

  /**
   * Import a key.
   */
  public async importKey<Jwk extends KmsJwkPrivate>(
    options: WithBackend<KmsImportKeyOptions<Jwk>, Backends>
  ): Promise<KmsImportKeyReturn<Jwk>> {
    const { backend, ...kmsOptions } = zParseWithErrorHandling(
      zWithBackend(zKmsImportKeyOptions),
      options,
      'Invalid options provided to importKey method'
    )

    const operation = {
      operation: 'importKey',
      privateJwk: options.privateJwk,
    } as const
    const kms = this.getKms(this.agentContext, backend, operation)

    const key = await kms.importKey(this.agentContext, kmsOptions)

    this.agentContext.config.logger.trace(
      `Imported key ${getJwkHumanDescription(key.publicJwk)} with key id '${key.keyId}'`
    )

    return key
  }

  /**
   * Get a public key, with the backend that holds it. Pass that backend to the operations that
   * follow on the same key, so the key is not looked up again to find its backend.
   */
  public async getPublicKey(
    options: WithBackend<KmsGetPublicKeyOptions, Backends>
  ): Promise<{ publicKey: KmsJwkPublic; backend: Backends[number]['backend'] }> {
    const { backend, keyId } = zParseWithErrorHandling(
      zWithBackend(zKmsGetPublicKeyOptions),
      options,
      'Invalid options provided to getPublicKey method'
    )

    if (backend) {
      const kms = this.getKms(this.agentContext, backend)
      const publicKey = await kms.getPublicKey(this.agentContext, keyId)

      if (!publicKey) {
        throw new KeyManagementKeyNotFoundError(keyId, [backend])
      }

      return { publicKey, backend: kms.backend }
    }

    const { publicKey, kms } = await this.getKmsForOperationAndKeyId(this.agentContext, keyId)
    return { publicKey, backend: kms.backend }
  }

  /**
   * Delete a key.
   */
  public async deleteKey(options: WithBackend<KmsDeleteKeyOptions, Backends>) {
    const { backend, ...kmsOptions } = zParseWithErrorHandling(
      zWithBackend(zKmsDeleteKeyOptions),
      options,
      'Invalid options provided to deleteKey method'
    )

    const operation = {
      operation: 'deleteKey',
    } as const
    const kms = this.getKms(this.agentContext, backend, operation)
    return await kms.deleteKey(this.agentContext, kmsOptions)
  }

  /**
   * Generate random bytes
   */
  public randomBytes(options: WithBackend<KmsRandomBytesOptions, Backends>) {
    const { backend, ...kmsOptions } = zParseWithErrorHandling(
      zWithBackend(zKmsRandomBytesOptions),
      options,
      'Invalid options provided to randomBytes method'
    )

    const operation = {
      operation: 'randomBytes',
    } as const
    const kms = this.getKms(this.agentContext, backend, operation)
    return kms.randomBytes(this.agentContext, kmsOptions)
  }

  /**
   * Get the kms associated with a specific `keyId`.
   *
   * This uses a naive approach of fetching the key for each configured kms
   * until it finds the registered key.
   *
   * In the future this approach might be optimized based on:
   * - caching
   * - keeping a registry
   * - backend specific key prefixes
   */
  private async getKmsForOperationAndKeyId(agentContext: AgentContext, keyId: string, operation?: KmsOperation) {
    for (const kms of this.keyManagementConfig.backends) {
      if (operation && !kms.isOperationSupported(agentContext, operation)) continue

      const publicKey = await kms.getPublicKey(this.agentContext, keyId)
      if (publicKey)
        return {
          publicKey,
          kms,
        }
    }

    throw new KeyManagementKeyNotFoundError(
      keyId,
      this.keyManagementConfig.backends.map((b) => b.backend),
      operation
        ? `The key may exist in one of the key management services in which case the key management service does not support the ${getKmsOperationHumanDescription(operation)}`
        : undefined
    )
  }

  /**
   * Get the kms to run an operation with a key. With one backend that supports the operation
   * it can avoid expensive lookups of the key.
   */
  private async getKmsForKeyOperation(keyId: string, operation: KmsOperation) {
    const supported = this.keyManagementConfig.backends.filter((kms) =>
      kms.isOperationSupported(this.agentContext, operation)
    )
    if (supported.length === 1) return supported[0]

    return (await this.getKmsForOperationAndKeyId(this.agentContext, keyId, operation)).kms
  }

  /**
   * Get the kms backend for a specific operation.
   *
   * If a backend is provided, it will be checked if the backend supports
   * the operation. Otherwise the default backend (the `defaultBackend` from
   * the `KeyManagementModuleConfig`, or the first registered backend if no
   * `defaultBackend` was configured) will be used if it supports the operation.
   * If the default backend does not support the operation, the first other
   * backend that supports the operation will be used and a warning will be logged.
   */
  private getKms(agentContext: AgentContext, backend?: string, operation?: KmsOperation) {
    const backends = this.keyManagementConfig.backends

    if (backend) {
      const kms = backends.find((kms) => kms.backend === backend)
      if (!kms) {
        const availableBackends = backends.map((kms) => `'${kms.backend}'`)
        throw new KeyManagementError(
          `No key management service is configured for backend '${backend}'. Available backends are ${availableBackends.join(
            ', '
          )}`
        )
      }

      if (operation && !kms.isOperationSupported(agentContext, operation)) {
        throw new KeyManagementError(
          `Key management service backend '${backend}' does not support ${getKmsOperationHumanDescription(operation)}`
        )
      }

      return kms
    }

    if (backends.length > 0) {
      const defaultKms = this.keyManagementConfig.defaultBackend
      if (!operation || defaultKms.isOperationSupported(agentContext, operation)) return defaultKms

      const fallbackKms = backends.find(
        (kms) => kms !== defaultKms && kms.isOperationSupported(agentContext, operation)
      )

      if (fallbackKms) {
        return fallbackKms
      }
    }

    throw new KeyManagementError(
      operation
        ? `No key management service backend found that supports ${getKmsOperationHumanDescription(operation)}`
        : 'No key management service backend found.'
    )
  }
}

function isResolvedKmsKey(key: KmsKeyReference | ResolvedKmsKey): key is ResolvedKmsKey {
  return 'backend' in key && 'jwk' in key && 'source' in key
}

function routingKeyId(key: KmsEncryptOptions['key'] | KmsDecryptOptions['key']): string | undefined {
  if (key.keyId) return key.keyId
  if (key.keyAgreement && 'keyId' in key.keyAgreement) return key.keyAgreement.keyId
  return undefined
}
