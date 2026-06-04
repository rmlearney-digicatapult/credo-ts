import type { AgentContext } from '../../agent/context'
import { CredoError } from '../../error'
import { injectable } from '../../plugins'
import type { Query, QueryOptions } from '../../storage/StorageService'
import { asArray } from '../../utils/array'
import {
  mapDataIntegrityIssuesToCredoError,
  type W3cV2DataIntegrityIssue,
  W3cV2DataIntegrityVerifiableCredential,
  W3cV2DataIntegrityVerifiablePresentation,
} from './data-integrity-v1'
import { W3cV2JwtVerifiableCredential, W3cV2JwtVerifiablePresentation } from './jwt-vc'
import { W3cV2JwtCredentialService } from './jwt-vc/W3cV2JwtCredentialService'
import type {
  W3cV2PresentationCredentialEntry,
  W3cV2VerifiableCredential,
  W3cV2VerifyCredentialResult,
  W3cV2VerifyPresentationResult,
} from './models'
import { ClaimFormat, W3cV2EnvelopedVerifiableCredential } from './models'
import type { W3cV2VerifiablePresentation } from './models/presentation/W3cV2VerifiablePresentation'
import { W3cV2CredentialRecord, W3cV2CredentialRepository } from './repository'
import {
  W3cV2SdJwtCredentialService,
  W3cV2SdJwtVerifiableCredential,
  W3cV2SdJwtVerifiablePresentation,
} from './sd-jwt-vc'
import { getVerificationMethodForJwt } from './v2-jwt-utils'
import type {
  W3cV2DiSignCredentialOptions,
  W3cV2DiSignPresentationOptions,
  W3cV2DiVerifyCredentialOptions,
  W3cV2DiVerifyPresentationOptions,
  W3cV2JwtVerifyCredentialOptions,
  W3cV2JwtVerifyPresentationOptions,
  W3cV2SdJwtVerifyCredentialOptions,
  W3cV2SdJwtVerifyPresentationOptions,
  W3cV2SignCredentialOptions,
  W3cV2SignPresentationOptions,
  W3cV2StoreCredentialOptions,
  W3cV2VerifyCredentialOptions,
  W3cV2VerifyPresentationOptions,
} from './W3cV2CredentialServiceOptions'

@injectable()
export class W3cV2CredentialService {
  private w3cV2CredentialRepository: W3cV2CredentialRepository
  private w3cV2SdJwtCredentialService: W3cV2SdJwtCredentialService
  private w3cV2JwtCredentialService: W3cV2JwtCredentialService

  public constructor(
    w3cV2CredentialRepository: W3cV2CredentialRepository,
    w3cV2SdJwtCredentialService: W3cV2SdJwtCredentialService,
    w3cV2JwtCredentialService: W3cV2JwtCredentialService
  ) {
    this.w3cV2CredentialRepository = w3cV2CredentialRepository
    this.w3cV2SdJwtCredentialService = w3cV2SdJwtCredentialService
    this.w3cV2JwtCredentialService = w3cV2JwtCredentialService
  }

  /**
   * Signs a credential
   *
   * @param credential the credential to be signed
   * @returns the signed credential
   */
  public async signCredential<Format extends ClaimFormat.JwtW3cVc | ClaimFormat.SdJwtW3cVc | ClaimFormat.DiVc>(
    agentContext: AgentContext,
    options: W3cV2SignCredentialOptions<Format>
  ): Promise<W3cV2VerifiableCredential<Format>> {
    if (options.format === ClaimFormat.JwtW3cVc) {
      const signed = await this.w3cV2JwtCredentialService.signCredential(agentContext, options)
      return signed as W3cV2VerifiableCredential<Format>
    }
    if (options.format === ClaimFormat.SdJwtW3cVc) {
      const signed = await this.w3cV2SdJwtCredentialService.signCredential(agentContext, options)
      return signed as W3cV2VerifiableCredential<Format>
    }
    if (options.format === ClaimFormat.DiVc) {
      this.throwDataIntegrityStubError('signCredential', ClaimFormat.DiVc, options as W3cV2DiSignCredentialOptions)
    }
    throw new CredoError(`Unsupported format in options. Format must be either 'vc+jwt', 'vc+sd-jwt', or 'di_vc'`)
  }

  /**
   * Verifies the signature(s) of a credential
   */
  public async verifyCredential(
    agentContext: AgentContext,
    options: W3cV2VerifyCredentialOptions
  ): Promise<W3cV2VerifyCredentialResult> {
    if (options.credential instanceof W3cV2JwtVerifiableCredential) {
      return this.w3cV2JwtCredentialService.verifyCredential(agentContext, options as W3cV2JwtVerifyCredentialOptions)
    }
    if (options.credential instanceof W3cV2SdJwtVerifiableCredential) {
      return this.w3cV2SdJwtCredentialService.verifyCredential(
        agentContext,
        options as W3cV2SdJwtVerifyCredentialOptions
      )
    }

    if (this.getClaimFormat(options.credential) === ClaimFormat.DiVc) {
      this.throwDataIntegrityStubError('verifyCredential', ClaimFormat.DiVc, options as W3cV2DiVerifyCredentialOptions)
    }

    throw new CredoError(
      'Unsupported credential type in options. Credential must be either a W3cV2JwtVerifiablePresentation or a W3cV2SdJwtVerifiablePresentation'
    )
  }

  /**
   * Signs a presentation including the credentials it includes
   *
   * @param presentation the presentation to be signed
   * @returns the signed presentation
   */
  public async signPresentation<Format extends ClaimFormat.JwtW3cVp | ClaimFormat.SdJwtW3cVp | ClaimFormat.DiVp>(
    agentContext: AgentContext,
    options: W3cV2SignPresentationOptions<Format>
  ): Promise<W3cV2VerifiablePresentation<Format>> {
    if (options.format === ClaimFormat.JwtW3cVp) {
      const signed = await this.w3cV2JwtCredentialService.signPresentation(agentContext, options)
      return signed as W3cV2VerifiablePresentation<Format>
    }
    if (options.format === ClaimFormat.SdJwtW3cVp) {
      const signed = await this.w3cV2SdJwtCredentialService.signPresentation(agentContext, options)
      return signed as W3cV2VerifiablePresentation<Format>
    }
    if (options.format === ClaimFormat.DiVp) {
      this.throwDataIntegrityStubError('signPresentation', ClaimFormat.DiVp, options as W3cV2DiSignPresentationOptions)
    }
    throw new CredoError(`Unsupported format in options. Format must be either 'vp+jwt', 'vp+sd-jwt', or 'di_vp'`)
  }

  /**
   * Verifies a presentation including the credentials it includes
   *
   * @param presentation the presentation to be verified
   * @returns the verification result
   */
  public async verifyPresentation(
    agentContext: AgentContext,
    options: W3cV2VerifyPresentationOptions
  ): Promise<W3cV2VerifyPresentationResult> {
    if (typeof options.presentation === 'string') {
      throw new CredoError(
        'String encoding of W3C V2 presentations is not yet supported. Please pass an object instance.'
      )
    }

    if (options.presentation instanceof W3cV2DataIntegrityVerifiablePresentation) {
      this.throwDataIntegrityStubError(
        'verifyPresentation',
        ClaimFormat.DiVp,
        options as W3cV2DiVerifyPresentationOptions
      )
    }

    if (this.getClaimFormat(options.presentation) === ClaimFormat.DiVp) {
      this.throwDataIntegrityStubError(
        'verifyPresentation',
        ClaimFormat.DiVp,
        options as W3cV2DiVerifyPresentationOptions
      )
    }

    const validationResults: W3cV2VerifyPresentationResult = {
      isValid: false,
      presentation: {
        isValid: false,
        validations: {},
      },
      credentialEntries: [],
    }

    let entries: W3cV2PresentationCredentialEntry[] = []
    let signerId: string | undefined
    let outerPresentationFormat: ClaimFormat.JwtW3cVp | ClaimFormat.SdJwtW3cVp

    if (options.presentation instanceof W3cV2JwtVerifiablePresentation) {
      outerPresentationFormat = ClaimFormat.JwtW3cVp
      const presentationResult = await this.w3cV2JwtCredentialService.verifyPresentation(
        agentContext,
        options as W3cV2JwtVerifyPresentationOptions
      )
      validationResults.presentation = presentationResult.presentation

      if (!presentationResult.presentation.isValid) {
        validationResults.isValid = false
        return validationResults
      }

      const holderId = options.presentation.resolvedPresentation.holderId
      if (holderId) {
        signerId = holderId
      } else {
        try {
          const verificationMethod = await getVerificationMethodForJwt(agentContext, options.presentation, [
            'authentication',
          ])
          signerId = verificationMethod.controller
        } catch {
          validationResults.isValid = false
          return validationResults
        }
      }
      entries = asArray(options.presentation.resolvedPresentation.verifiableCredential)
    } else if (options.presentation instanceof W3cV2SdJwtVerifiablePresentation) {
      outerPresentationFormat = ClaimFormat.SdJwtW3cVp
      const presentationResult = await this.w3cV2SdJwtCredentialService.verifyPresentation(
        agentContext,
        options as W3cV2SdJwtVerifyPresentationOptions
      )
      validationResults.presentation = presentationResult.presentation

      if (!presentationResult.presentation.isValid) {
        validationResults.isValid = false
        return validationResults
      }

      const holderId = options.presentation.resolvedPresentation.holderId
      if (holderId) {
        signerId = holderId
      } else {
        try {
          const verificationMethod = await getVerificationMethodForJwt(agentContext, options.presentation, [
            'authentication',
          ])
          signerId = verificationMethod.controller
        } catch {
          validationResults.isValid = false
          return validationResults
        }
      }
      entries = asArray(options.presentation.resolvedPresentation.verifiableCredential)
    } else {
      throw new CredoError(
        'Unsupported credential type in options. Presentation must be either a W3cV2JwtVerifiablePresentation or a W3cV2SdJwtVerifiablePresentation'
      )
    }

    validationResults.credentialEntries = await Promise.all(
      entries.map(async (entry) => {
        if (entry instanceof W3cV2DataIntegrityVerifiableCredential) {
          return this.createUnsupportedCredentialEntryResult(
            "Data Integrity format 'di_vc' is not yet implemented for W3C V2 credential verification. Support is currently limited to parsing/modeling and explicit unsupported-result signaling."
          )
        }

        if (!(entry instanceof W3cV2EnvelopedVerifiableCredential)) {
          return this.createUnsupportedCredentialEntryResult('Unsupported credential entry type in presentation.')
        }

        let credentialResult: W3cV2VerifyCredentialResult
        if (entry.envelopedCredential instanceof W3cV2JwtVerifiableCredential) {
          if (outerPresentationFormat !== ClaimFormat.JwtW3cVp) {
            return this.createUnsupportedCredentialEntryResult(
              "Credential entry uses 'vc+jwt' inside a non-'vp+jwt' presentation. VC-JOSE-COSE requires enclosed credentials to use the securing mechanism of the enclosing VP profile."
            )
          }

          credentialResult = await this.w3cV2JwtCredentialService.verifyCredential(agentContext, {
            credential: entry.envelopedCredential,
          } as W3cV2JwtVerifyCredentialOptions)
        } else if (entry.envelopedCredential instanceof W3cV2SdJwtVerifiableCredential) {
          if (outerPresentationFormat !== ClaimFormat.SdJwtW3cVp) {
            return this.createUnsupportedCredentialEntryResult(
              "Credential entry uses 'vc+sd-jwt' inside a non-'vp+sd-jwt' presentation. VC-JOSE-COSE requires enclosed credentials to use the securing mechanism of the enclosing VP profile."
            )
          }

          credentialResult = await this.w3cV2SdJwtCredentialService.verifyCredential(agentContext, {
            credential: entry.envelopedCredential,
          } as W3cV2SdJwtVerifyCredentialOptions)
        } else {
          return this.createUnsupportedCredentialEntryResult('Unsupported enclosed credential type in presentation entry.')
        }

        return this.mergeCredentialSubjectAuthenticationValidation(
          credentialResult,
          signerId,
          entry.resolvedCredential.credentialSubjectIds
        )
      })
    )

    validationResults.isValid =
      validationResults.presentation.isValid && validationResults.credentialEntries.every((entry) => entry.isValid)

    return validationResults
  }

  // TODO: replace this stub with DI component integration once vc/data-integrity-v1 and w3c-di are ported.
  private throwDataIntegrityStubError(
    operation: 'signCredential' | 'verifyCredential' | 'signPresentation' | 'verifyPresentation',
    claimFormat: ClaimFormat.DiVc | ClaimFormat.DiVp,
    _options:
      | W3cV2DiSignCredentialOptions
      | W3cV2DiVerifyCredentialOptions
      | W3cV2DiSignPresentationOptions
      | W3cV2DiVerifyPresentationOptions,
    issues?: W3cV2DataIntegrityIssue[]
  ): never {
    const cause = mapDataIntegrityIssuesToCredoError({
      operation,
      claimFormat,
      issues,
    })

    throw new CredoError(
      `Data Integrity format '${claimFormat}' is not supported by ${operation} on this branch. ` +
        `Only DI stubs are present in chore/vc2-spec-alignment pending a dedicated DI port.`,
      { cause }
    )
  }

  private getClaimFormat(value: unknown): string | undefined {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined

    const candidate = value as { claimFormat?: unknown }
    return typeof candidate.claimFormat === 'string' ? candidate.claimFormat : undefined
  }

  private createUnsupportedCredentialEntryResult(message: string) {
    return {
      isValid: false,
      error: new CredoError(message),
      validations: {},
    }
  }

  private mergeCredentialSubjectAuthenticationValidation(
    credentialResult: W3cV2VerifyCredentialResult,
    signerId: string,
    credentialSubjectIds: string[]
  ) {
    const presentationAuthenticatesCredentialSubject = credentialSubjectIds.some((subjectId) => signerId === subjectId)

    const credentialSubjectAuthentication =
      credentialSubjectIds.length > 0 && !presentationAuthenticatesCredentialSubject
        ? {
            isValid: false,
            error: new CredoError(
              'Credential has one or more credentialSubject ids, but presentation does not authenticate credential subject'
            ),
          }
        : {
            isValid: true,
          }

    return {
      ...credentialResult,
      isValid: credentialResult.isValid && credentialSubjectAuthentication.isValid,
      validations: {
        ...credentialResult.validations,
        credentialSubjectAuthentication,
      },
    }
  }

  /**
   * Writes a credential to storage
   *
   * @param record the credential to be stored
   * @returns the credential record that was written to storage
   */
  public async storeCredential(
    agentContext: AgentContext,
    options: W3cV2StoreCredentialOptions
  ): Promise<W3cV2CredentialRecord> {
    // Store the w3cV2 credential record
    await this.w3cV2CredentialRepository.save(agentContext, options.record)

    return options.record
  }

  public async removeCredentialRecord(agentContext: AgentContext, id: string) {
    await this.w3cV2CredentialRepository.deleteById(agentContext, id)
  }

  public async getAllCredentialRecords(agentContext: AgentContext): Promise<W3cV2CredentialRecord[]> {
    return await this.w3cV2CredentialRepository.getAll(agentContext)
  }

  public async getCredentialRecordById(agentContext: AgentContext, id: string): Promise<W3cV2CredentialRecord> {
    return await this.w3cV2CredentialRepository.getById(agentContext, id)
  }

  public async findCredentialsByQuery(
    agentContext: AgentContext,
    query: Query<W3cV2CredentialRecord>,
    queryOptions?: QueryOptions
  ): Promise<W3cV2VerifiableCredential[]> {
    const result = await this.w3cV2CredentialRepository.findByQuery(agentContext, query, queryOptions)
    return result.map((record) => record.firstCredential)
  }

  public async findCredentialRecordByQuery(
    agentContext: AgentContext,
    query: Query<W3cV2CredentialRecord>
  ): Promise<W3cV2VerifiableCredential | undefined> {
    const result = await this.w3cV2CredentialRepository.findSingleByQuery(agentContext, query)
    return result?.firstCredential
  }
}
