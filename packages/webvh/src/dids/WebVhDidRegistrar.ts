import type {
  AgentContext,
  DidCreateOptions,
  DidCreateResult,
  DidDeactivateOptions,
  DidDeactivateResult,
  DidDocumentKey,
  DidRegistrar,
  DidUpdateOptions,
  DidUpdateResult,
} from '@credo-ts/core'

import { CredoError, DidDocument, DidDocumentRole, DidRecord, DidRepository } from '@credo-ts/core'
import {
  type CreateDIDOptions,
  createDID,
  type DeactivateDIDOptions,
  deactivateDID,
  type UpdateDIDOptions,
  type UpdateDIDResult,
  updateDID,
  type WitnessProofFileEntry,
} from 'didwebvh-ts'
import {
  createWebVhControllerSigner,
  failedWebVhRegistration,
  getWebVhControllerMetadata,
  getWebVhDidLog,
  getWebVhDidRecord,
  getWebVhDomainTag,
  persistWebVhDocumentWrite,
  prepareWebVhDocumentWrite,
  validateWebVhControllerKeys,
  validateWebVhDocumentKeys,
} from './WebVhDidController'
import { WebVhDidCrypto } from './WebVhDidCrypto'
import { WebVhDidRecordMetadataKeys, type WebVhUpdateKeyKmsKeyIds } from './webVhTypes'

export interface WebVhDidCreateOptions extends DidCreateOptions {
  method: 'webvh'
  didDocument: DidDocument
  options: Omit<CreateDIDOptions, 'didDocument' | 'signer' | 'verifier' | 'address'> & {
    address: string
    keys: DidDocumentKey[]
    updateKeyKmsKeyIds: WebVhUpdateKeyKmsKeyIds
  }
}

export interface WebVhDidUpdateOptions extends DidUpdateOptions {
  didDocument: DidDocument
  options?: Omit<UpdateDIDOptions, 'didDocument' | 'signer' | 'verifier' | 'fetch' | 'log'> & {
    keys?: DidDocumentKey[]
    updateKeyKmsKeyIds?: WebVhUpdateKeyKmsKeyIds
  }
}

export interface WebVhDidDeactivateOptions extends DidDeactivateOptions {
  options?: Pick<DeactivateDIDOptions, 'updateKeys' | 'witnessProofs'>
}

export class WebVhDidRegistrar implements DidRegistrar {
  public readonly supportedMethods: string[] = ['webvh']

  /**
   * Creates and stores a complete caller-authored document using existing KMS keys; publication is caller-managed.
   *
   * @param agentContext Agent context providing storage and KMS.
   * @param options Complete document, upstream create options, and KMS mappings.
   * @returns Finished registration with upstream metadata, or a failed registration with its reason.
   */
  public async create(agentContext: AgentContext, options: WebVhDidCreateOptions): Promise<DidCreateResult> {
    try {
      this.assertCompleteDocument(options.didDocument)
      const { keys: inputKeys, updateKeyKmsKeyIds, ...upstreamOptions } = options.options
      const { updateKeys } = upstreamOptions
      if (!Array.isArray(inputKeys) || !updateKeyKmsKeyIds) {
        throw new CredoError('Create options require keys and updateKeyKmsKeyIds')
      }
      const repository = agentContext.dependencyManager.resolve(DidRepository)
      const keys = await validateWebVhDocumentKeys(agentContext, options.didDocument, inputKeys)
      const controllerKeys = await validateWebVhControllerKeys(agentContext, updateKeyKmsKeyIds)
      const signer = createWebVhControllerSigner(agentContext, updateKeys, controllerKeys)
      const result = await createDID({
        ...upstreamOptions,
        didDocument: { ...options.didDocument.toJSON(), id: options.didDocument.id },
        signer,
        verifier: new WebVhDidCrypto(agentContext),
      })
      const didDocument = DidDocument.fromJSON(result.doc)
      const validatedKeys = await validateWebVhDocumentKeys(agentContext, didDocument, keys)
      const domain = getWebVhDomainTag(result.did)
      const record = new DidRecord({
        did: result.did,
        didDocument,
        role: DidDocumentRole.Created,
        keys: validatedKeys,
        tags: { domain },
      })
      this.persistResult(record, result, controllerKeys)
      await repository.save(agentContext, record)
      return this.finished(result, didDocument)
    } catch (error) {
      return this.failed(agentContext, 'create', error)
    }
  }

  /**
   * Replaces the complete document using authenticated controller keys, retaining matching document-key mappings when omitted.
   *
   * @param agentContext Agent context providing storage, KMS, and configured fetch.
   * @param options Controlled DID, replacement document, and optional upstream options and KMS mappings.
   * @returns Finished registration with upstream metadata, or a failed registration with its reason.
   */
  public async update(agentContext: AgentContext, options: WebVhDidUpdateOptions): Promise<DidUpdateResult> {
    try {
      this.assertCompleteDocument(options.didDocument)
      if (options.didDocumentOperation && options.didDocumentOperation !== 'setDidDocument') {
        throw new CredoError('notSupported: WebVH update requires setDidDocument with a complete DID document')
      }
      const prepared = await prepareWebVhDocumentWrite(
        agentContext,
        options.did,
        options.didDocument,
        options.options ?? {}
      )
      const result = await updateDID(prepared.writerOptions)
      const didDocument = await persistWebVhDocumentWrite(agentContext, prepared, result)
      return this.finished(result, didDocument)
    } catch (error) {
      return this.failed(agentContext, 'update', error)
    }
  }

  /**
   * Stores a signed deactivation entry; active pre-rotation must first be cleared by a separate update.
   *
   * @param agentContext Agent context providing storage, KMS, and configured fetch.
   * @param options Controlled DID and optional update keys and witness proofs.
   * @returns Finished deactivation with upstream metadata, or a failed registration with its reason.
   */
  public async deactivate(
    agentContext: AgentContext,
    options: WebVhDidDeactivateOptions
  ): Promise<DidDeactivateResult> {
    try {
      const record = await getWebVhDidRecord(agentContext, options.did)
      const state = getWebVhControllerMetadata(record)
      const controllerKeys =
        record.metadata.get<WebVhUpdateKeyKmsKeyIds>(WebVhDidRecordMetadataKeys.UpdateKeyKmsKeyIds) ?? {}
      const signer = createWebVhControllerSigner(agentContext, state.updateKeys, controllerKeys)
      const result = await deactivateDID({
        log: getWebVhDidLog(record),
        updateKeys: options.options?.updateKeys,
        witnessProofs:
          options.options?.witnessProofs ??
          record.metadata.get<WitnessProofFileEntry[]>(WebVhDidRecordMetadataKeys.WitnessProofs) ??
          undefined,
        signer,
        verifier: new WebVhDidCrypto(agentContext),
        fetch: agentContext.config.fetch.bind(agentContext.config),
      })
      const didDocument = DidDocument.fromJSON(result.doc)
      this.persistResult(record, result, controllerKeys)
      if (options.options?.witnessProofs)
        record.metadata.set(WebVhDidRecordMetadataKeys.WitnessProofs, options.options.witnessProofs)
      await agentContext.dependencyManager.resolve(DidRepository).update(agentContext, record)
      return this.finished(result, didDocument)
    } catch (error) {
      return this.failed(agentContext, 'deactivate', error)
    }
  }

  private assertCompleteDocument(document: DidDocument) {
    if (!(document instanceof DidDocument) || !document.id) {
      throw new CredoError('notSupported: WebVH requires a complete DidDocument with an id')
    }
  }

  private persistResult(record: DidRecord, result: UpdateDIDResult, controllerKeys: WebVhUpdateKeyKmsKeyIds) {
    record.did = result.did
    record.didDocument = DidDocument.fromJSON(result.doc)
    record.metadata.set(WebVhDidRecordMetadataKeys.DidLog, result.log)
    record.metadata.set(WebVhDidRecordMetadataKeys.ControllerMetadata, result.meta)
    record.metadata.set(WebVhDidRecordMetadataKeys.UpdateKeyKmsKeyIds, controllerKeys)
  }

  private finished(result: UpdateDIDResult, didDocument: DidDocument): DidCreateResult {
    return {
      didDocumentMetadata: result.meta,
      didRegistrationMetadata: {},
      didState: { state: 'finished', did: result.did, didDocument },
    }
  }

  private failed(agentContext: AgentContext, operation: string, error: unknown): DidCreateResult {
    return failedWebVhRegistration(agentContext, operation, error)
  }
}
