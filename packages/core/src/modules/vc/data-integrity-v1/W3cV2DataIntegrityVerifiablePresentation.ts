import { CredoError } from '../../../error'
import { JsonEncoder, JsonTransformer, MessageValidator } from '../../../utils'
import { ClaimFormat } from '../models/ClaimFormat'
import { W3cV2Presentation } from '../models/presentation/W3cV2Presentation'

export type W3cV2DataIntegritySecuredPresentation = Record<string, unknown> & { proof: unknown }

export interface W3cV2DataIntegrityVerifiablePresentationOptions {
  securedPresentation: W3cV2DataIntegritySecuredPresentation
}

/**
 * Represents a Verifiable Presentation secured with Data Integrity proof(s).
 *
 * @see https://www.w3.org/TR/vc-data-integrity/
 */
export class W3cV2DataIntegrityVerifiablePresentation {
  public constructor(options: W3cV2DataIntegrityVerifiablePresentationOptions) {
    this.securedPresentation = options.securedPresentation
    this.resolvedPresentation = JsonTransformer.fromJSON(options.securedPresentation, W3cV2Presentation, {
      validate: false,
    })

    // Validates the presentation structure and proof presence
    this.validate()
  }

  public static fromObject(presentation: W3cV2DataIntegritySecuredPresentation) {
    return new W3cV2DataIntegrityVerifiablePresentation({
      securedPresentation: presentation,
    })
  }

  public static fromDataUri(dataUri: string) {
    if (!dataUri.startsWith('data:')) {
      throw new CredoError('Invalid Data Integrity Verifiable Presentation: value is not a valid data URI')
    }

    const mimeTypeData = dataUri.slice(5)
    const commaIndex = mimeTypeData.indexOf(',')
    if (commaIndex === -1) {
      throw new CredoError('Invalid Data Integrity Verifiable Presentation: data URI is missing comma separator')
    }

    const mimeType = mimeTypeData.slice(0, commaIndex)
    if (mimeType !== 'application/vp+di') {
      throw new CredoError(`Unsupported Data Integrity Verifiable Presentation encoding: ${mimeType}`)
    }

    const payload = mimeTypeData.slice(commaIndex + 1)
    return W3cV2DataIntegrityVerifiablePresentation.fromDataUriPayload(payload)
  }

  public static fromDataUriPayload(payload: string) {
    try {
      const parsed = JSON.parse(payload)
      if (isEmbeddedDataIntegrityPresentation(parsed)) {
        return W3cV2DataIntegrityVerifiablePresentation.fromObject(parsed)
      }
    } catch {
      // Ignore JSON parse errors and try base64url below.
    }

    try {
      const decoded = JsonEncoder.fromBase64Url(payload)
      if (isEmbeddedDataIntegrityPresentation(decoded)) {
        return W3cV2DataIntegrityVerifiablePresentation.fromObject(decoded)
      }
    } catch {
      // Fall through to explicit error below.
    }

    throw new CredoError('Invalid Data Integrity Verifiable Presentation: vp+di payload is not valid JSON')
  }

  /**
   * The original presentation object with embedded Data Integrity proof(s).
   */
  public readonly securedPresentation: W3cV2DataIntegritySecuredPresentation

  /**
   * Resolved presentation is the fully resolved {@link W3cV2Presentation} instance.
   */
  public readonly resolvedPresentation: W3cV2Presentation

  /**
   * The JSON representation of this presentation.
   */
  public get encoded() {
    return JSON.stringify(this.securedPresentation)
  }

  /**
   * The {@link ClaimFormat} of the presentation.
   *
   * For W3C VP Data Integrity presentations this is always `di_vp`.
   */
  public get claimFormat(): ClaimFormat.DiVp {
    return ClaimFormat.DiVp
  }

  /**
   * Validates the presentation and proof structure.
   */
  public validate() {
    // Validate the resolved presentation according to the data model
    MessageValidator.validateSync(this.resolvedPresentation)

    // Validate that proof field exists and is properly structured
    const proof = this.securedPresentation.proof
    if (!proof) {
      throw new CredoError('The provided presentation does not have a proof field.')
    }

    // Proof should be either a single proof object or an array of proofs
    if (typeof proof !== 'object') {
      throw new CredoError('The proof field must be an object or array of objects.')
    }

    if (
      !Array.isArray(proof) &&
      typeof proof === 'object' &&
      (!('type' in proof) || proof.type !== 'DataIntegrityProof')
    ) {
      throw new CredoError('The proof must have type "DataIntegrityProof".')
    }

    if (Array.isArray(proof)) {
      for (const p of proof) {
        if (typeof p !== 'object' || !('type' in p) || p.type !== 'DataIntegrityProof') {
          throw new CredoError('All proofs in the proof array must have type "DataIntegrityProof".')
        }
      }
    }
  }
}

function isEmbeddedDataIntegrityPresentation(value: unknown): value is W3cV2DataIntegritySecuredPresentation {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false

  return 'proof' in value
}
