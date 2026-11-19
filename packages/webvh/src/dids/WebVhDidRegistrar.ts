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

import { CredoError, type DidDocument } from '@credo-ts/core'
import {
  type CreateDIDOptions,
  createDID,
  type DeactivateDIDOptions,
  deactivateDID,
  defaultVerifier,
  type UpdateDIDOptions,
  type UpdateDIDResult,
  updateDID,
  type WitnessProofFileEntry,
} from 'didwebvh-ts'
import {
  assertWebVhDidDocument,
  createWebVhControllerSigner,
  failedWebVhRegistration,
  getWebVhControllerMetadata,
  getWebVhDidLog,
  getWebVhDidRecord,
  persistWebVhDocumentWrite,
  prepareWebVhDocumentWrite,
  validateWebVhControllerKeys,
  validateWebVhDocumentKeys,
  WebVhRegistrationError,
} from './WebVhDidController'
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
      assertWebVhDidDocument(options.didDocument)
      const { keys: inputKeys, updateKeyKmsKeyIds, ...upstreamOptions } = options.options
      if (!Array.isArray(inputKeys) || !updateKeyKmsKeyIds) {
        throw new CredoError('Create options require keys and updateKeyKmsKeyIds')
      }
      const keys = await validateWebVhDocumentKeys(agentContext, options.didDocument, inputKeys)
      const controllerKeys = await validateWebVhControllerKeys(agentContext, updateKeyKmsKeyIds)
      const signer = createWebVhControllerSigner(agentContext, upstreamOptions.updateKeys, controllerKeys)
      const result = await createDID({
        ...upstreamOptions,
        didDocument: { ...options.didDocument.toJSON(), id: options.didDocument.id },
        signer,
        verifier: defaultVerifier,
      })
      const didDocument = await persistWebVhDocumentWrite(agentContext, { controllerKeys, keys }, result)
      return this.finished(result, didDocument)
    } catch (error) {
      return failedWebVhRegistration(agentContext, 'create', error)
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
      if (options.didDocumentOperation && options.didDocumentOperation !== 'setDidDocument') {
        throw new WebVhRegistrationError(
          'notSupported',
          'WebVH update requires setDidDocument with a complete DID document'
        )
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
      return failedWebVhRegistration(agentContext, 'update', error)
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
      const witnessProofs =
        options.options?.witnessProofs ??
        record.metadata.get<WitnessProofFileEntry[]>(WebVhDidRecordMetadataKeys.WitnessProofs) ??
        undefined
      const result = await deactivateDID({
        log: getWebVhDidLog(record),
        updateKeys: options.options?.updateKeys,
        witnessProofs,
        signer,
        verifier: defaultVerifier,
        fetch: agentContext.config.fetch.bind(agentContext.config),
      })
      const didDocument = await persistWebVhDocumentWrite(
        agentContext,
        { record, controllerKeys, witnessProofs },
        result
      )
      return this.finished(result, didDocument)
    } catch (error) {
      return failedWebVhRegistration(agentContext, 'deactivate', error)
    }
  }

  private finished(result: UpdateDIDResult, didDocument: DidDocument): DidCreateResult {
    return {
      didDocumentMetadata: result.meta,
      didRegistrationMetadata: {},
      didState: { state: 'finished', did: result.did, didDocument },
    }
  }
}
