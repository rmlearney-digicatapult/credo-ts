import {
  type AgentContext,
  CredoError,
  type DidCreateResult,
  DidDocument,
  type DidDocumentKey,
  DidDocumentRole,
  type DidRecord,
  DidRepository,
  getPublicJwkFromVerificationMethod,
  Kms,
  parseDid,
  type VerificationMethod,
} from '@credo-ts/core'
import {
  type DIDLog,
  resolveDIDFromLog,
  type UpdateDIDOptions,
  type UpdateDIDResult,
  type WitnessProofFileEntry,
} from 'didwebvh-ts'

import { WebVhDidCrypto } from './WebVhDidCrypto'
import { WebVhDidCryptoSigner } from './WebVhDidCryptoSigner'
import { WebVhDidRecordMetadataKeys, type WebVhUpdateKeyKmsKeyIds } from './webVhTypes'

export async function getWebVhDidRecord(agentContext: AgentContext, did: string) {
  const record = await agentContext.dependencyManager.resolve(DidRepository).findSingleByQuery(agentContext, {
    role: DidDocumentRole.Created,
    did,
    method: 'webvh',
  })
  if (!record) throw new CredoError(`notFound: controlled WebVH DID '${did}' not found`)
  return record
}

export function getWebVhDidLog(record: DidRecord) {
  const log = record.metadata.get<DIDLog>(WebVhDidRecordMetadataKeys.DidLog)
  if (!log?.length) throw new CredoError(`unknownError: controlled DID '${record.did}' has no persisted log`)
  return log
}

export async function resolveWebVhControllerState(
  agentContext: AgentContext,
  record: DidRecord,
  witnessProofs?: WitnessProofFileEntry[]
) {
  const result = await resolveDIDFromLog(getWebVhDidLog(record), {
    verifier: new WebVhDidCrypto(agentContext),
    fetch: agentContext.config.fetch.bind(agentContext.config),
    witnessProofs:
      witnessProofs ??
      record.metadata.get<WitnessProofFileEntry[]>(WebVhDidRecordMetadataKeys.WitnessProofs) ??
      undefined,
  })
  if (result.didResolutionMetadata.error) {
    throw new CredoError(result.didResolutionMetadata.message ?? result.didResolutionMetadata.error)
  }
  return result
}

export async function prepareWebVhDocumentWrite(
  agentContext: AgentContext,
  did: string,
  didDocument: DidDocument,
  input: Omit<UpdateDIDOptions, 'didDocument' | 'signer' | 'verifier' | 'fetch' | 'log'> & {
    keys?: DidDocumentKey[]
    updateKeyKmsKeyIds?: WebVhUpdateKeyKmsKeyIds
  }
) {
  if (!(didDocument instanceof DidDocument) || !didDocument.id) {
    throw new CredoError('notSupported: WebVH requires a complete DidDocument with an id')
  }
  const record = await getWebVhDidRecord(agentContext, did)
  const { keys, updateKeyKmsKeyIds, ...upstreamOptions } = input
  const state = await resolveWebVhControllerState(agentContext, record, input.witnessProofs)
  const validatedControllerKeys = updateKeyKmsKeyIds
    ? await validateWebVhControllerKeys(agentContext, updateKeyKmsKeyIds)
    : undefined
  const controllerKeys = {
    ...record.metadata.get<WebVhUpdateKeyKmsKeyIds>(WebVhDidRecordMetadataKeys.UpdateKeyKmsKeyIds),
    ...validatedControllerKeys?.mappings,
  }
  const validatedKeys = keys ? await validateWebVhDocumentKeys(agentContext, didDocument, keys) : undefined
  const authorizedKeys = state.didDocumentMetadata.prerotation ? input.updateKeys : state.didDocumentMetadata.updateKeys
  if (!Array.isArray(authorizedKeys) || !authorizedKeys.every((key): key is string => typeof key === 'string')) {
    throw new CredoError('updateKeys must be provided while pre-rotation is active')
  }
  const signer = await selectWebVhControllerSigner(
    agentContext,
    authorizedKeys,
    controllerKeys,
    validatedControllerKeys?.resolvedKeys
  )
  const writerOptions: UpdateDIDOptions = {
    ...upstreamOptions,
    log: getWebVhDidLog(record),
    didDocument: { ...didDocument.toJSON(), id: didDocument.id },
    witnessProofs:
      input.witnessProofs ??
      record.metadata.get<WitnessProofFileEntry[]>(WebVhDidRecordMetadataKeys.WitnessProofs) ??
      undefined,
    signer,
    verifier: new WebVhDidCrypto(agentContext),
    fetch: agentContext.config.fetch.bind(agentContext.config),
  }
  return { record, controllerKeys, keys: validatedKeys, writerOptions }
}

export async function persistWebVhDocumentWrite(
  agentContext: AgentContext,
  prepared: Awaited<ReturnType<typeof prepareWebVhDocumentWrite>>,
  result: UpdateDIDResult
) {
  const { record, controllerKeys, writerOptions } = prepared
  const didDocument = DidDocument.fromJSON(result.doc)
  const keys = await validateWebVhDocumentKeys(
    agentContext,
    didDocument,
    prepared.keys ?? retainWebVhDocumentKeys(record.didDocument, didDocument, record.keys ?? [])
  )
  if (result.did !== record.did) {
    record.setTags({ domain: parseDid(result.did).id.split(':').slice(1).map(decodeURIComponent).join(':') })
  }
  record.did = result.did
  record.didDocument = didDocument
  record.keys = keys
  record.metadata.set(WebVhDidRecordMetadataKeys.DidLog, result.log)
  record.metadata.set(WebVhDidRecordMetadataKeys.ControllerMetadata, result.meta)
  record.metadata.set(WebVhDidRecordMetadataKeys.UpdateKeyKmsKeyIds, controllerKeys)
  if (writerOptions.witnessProofs)
    record.metadata.set(WebVhDidRecordMetadataKeys.WitnessProofs, writerOptions.witnessProofs)
  await agentContext.dependencyManager.resolve(DidRepository).update(agentContext, record)
  return didDocument
}

export function failedWebVhRegistration(
  agentContext: AgentContext,
  operation: string,
  error: unknown
): DidCreateResult {
  agentContext.config.logger.error(`WebVH ${operation} failed`, { error })
  const message = error instanceof Error ? error.message : String(error)
  const reason =
    error instanceof Kms.KeyManagementKeyNotFoundError
      ? `notFound: ${message}`
      : /^(notFound|notSupported|unknownError):/.test(message)
        ? message
        : `unknownError: ${message}`
  return {
    didDocumentMetadata: {},
    didRegistrationMetadata: {},
    didState: { state: 'failed', reason },
  }
}

export async function getWebVhKmsPublicJwk(
  agentContext: AgentContext,
  keyReference: Kms.KmsKeyReference
): Promise<{ publicJwk: Kms.PublicJwk; kmsBackend: string }> {
  const { publicKey: key, backend } = await agentContext.dependencyManager
    .resolve(Kms.KeyManagementApi)
    .getPublicKey({ keyId: keyReference.keyId, backend: keyReference.kmsBackend })
  if (key.kty === 'oct') throw new CredoError(`KMS key '${keyReference.keyId}' must be asymmetric`)
  return { publicJwk: Kms.PublicJwk.fromPublicJwk(key), kmsBackend: backend }
}

type ResolvedWebVhKmsPublicKey = Awaited<ReturnType<typeof getWebVhKmsPublicJwk>>

export async function createWebVhKmsSigner(
  agentContext: AgentContext,
  keyReference: Kms.KmsKeyReference,
  resolvedKey?: ResolvedWebVhKmsPublicKey
) {
  const { publicJwk, kmsBackend } = resolvedKey ?? (await getWebVhKmsPublicJwk(agentContext, keyReference))
  if (!publicJwk.is(Kms.Ed25519PublicJwk)) {
    throw new CredoError(`KMS key '${keyReference.keyId}' must be Ed25519 to sign a WebVH proof`)
  }
  return new WebVhDidCryptoSigner(agentContext, publicJwk.fingerprint, keyReference.keyId, kmsBackend)
}

export type ValidatedWebVhControllerKeys = {
  mappings: WebVhUpdateKeyKmsKeyIds
  resolvedKeys: Map<string, ResolvedWebVhKmsPublicKey>
}

export async function validateWebVhControllerKeys(
  agentContext: AgentContext,
  mappings: WebVhUpdateKeyKmsKeyIds
): Promise<ValidatedWebVhControllerKeys> {
  const validatedMappings: WebVhUpdateKeyKmsKeyIds = {}
  const resolvedKeys = new Map<string, ResolvedWebVhKmsPublicKey>()
  for (const [multikey, keyReference] of Object.entries(mappings)) {
    const resolvedKey = await getWebVhKmsPublicJwk(agentContext, keyReference)
    const { publicJwk, kmsBackend } = resolvedKey
    if (publicJwk.fingerprint !== multikey) {
      throw new CredoError(`Controller update key '${multikey}' does not match KMS key '${keyReference.keyId}'`)
    }
    validatedMappings[multikey] = { keyId: keyReference.keyId, kmsBackend }
    resolvedKeys.set(multikey, resolvedKey)
  }
  return { mappings: validatedMappings, resolvedKeys }
}

export async function selectWebVhControllerSigner(
  agentContext: AgentContext,
  updateKeys: string[],
  mappings: WebVhUpdateKeyKmsKeyIds,
  resolvedKeys?: ReadonlyMap<string, ResolvedWebVhKmsPublicKey>
) {
  for (const updateKey of updateKeys) {
    // Upstream accepts did:key inputs but stores bare multikeys in authenticated metadata.
    const parsed = updateKey.startsWith('did:key:') ? parseDid(updateKey) : undefined
    const multikey = parsed?.id ?? updateKey
    if (parsed?.fragment && parsed.fragment !== multikey) {
      throw new CredoError(`Controller update key '${updateKey}' has a mismatched did:key fragment`)
    }
    const keyReference = mappings[multikey]
    if (keyReference) {
      const signer = await createWebVhKmsSigner(agentContext, keyReference, resolvedKeys?.get(multikey))
      if (signer.getVerificationMethodId() !== `did:key:${multikey}#${multikey}`) {
        throw new CredoError(`Controller update key '${multikey}' does not match KMS key '${keyReference.keyId}'`)
      }
      return signer
    }
  }
  throw new CredoError('unknownError: no authorized controller update key has a Credo KMS mapping')
}

function tryDereferenceDocumentKey(document: DidDocument, relativeId: string): VerificationMethod | undefined {
  try {
    return document.dereferenceKey(relativeId)
  } catch (error) {
    if (
      error instanceof CredoError &&
      error.message.startsWith(`Unable to locate verification method with id '${relativeId}' in purposes `)
    ) {
      return undefined
    }
    throw error
  }
}

export async function validateWebVhDocumentKeys(
  agentContext: AgentContext,
  document: DidDocument,
  keys: DidDocumentKey[]
): Promise<DidDocumentKey[]> {
  const resolvedKeys: DidDocumentKey[] = []
  for (const { didDocumentRelativeKeyId, kmsKeyId, kmsBackend } of keys) {
    if (!didDocumentRelativeKeyId.startsWith('#') || didDocumentRelativeKeyId.length === 1) {
      throw new CredoError('Document KMS mappings require a caller-authored relative key ID such as #key-1')
    }
    const method = tryDereferenceDocumentKey(document, didDocumentRelativeKeyId)
    if (!method) throw new CredoError(`Document key '${didDocumentRelativeKeyId}' is not present in the DID document`)
    const { publicJwk, kmsBackend: resolvedBackend } = await getWebVhKmsPublicJwk(agentContext, {
      keyId: kmsKeyId,
      kmsBackend,
    })
    if (!getPublicJwkFromVerificationMethod(method).equals(publicJwk)) {
      throw new CredoError(`Document key '${didDocumentRelativeKeyId}' does not match KMS key '${kmsKeyId}'`)
    }
    resolvedKeys.push({ didDocumentRelativeKeyId, kmsKeyId, kmsBackend: resolvedBackend })
  }
  return resolvedKeys
}

export function retainWebVhDocumentKeys(
  previousDocument: DidDocument | undefined,
  document: DidDocument,
  keys: DidDocumentKey[]
) {
  return keys.filter(({ didDocumentRelativeKeyId }) => {
    const previous = previousDocument && tryDereferenceDocumentKey(previousDocument, didDocumentRelativeKeyId)
    const next = tryDereferenceDocumentKey(document, didDocumentRelativeKeyId)
    return (
      previous && next && getPublicJwkFromVerificationMethod(previous).equals(getPublicJwkFromVerificationMethod(next))
    )
  })
}
