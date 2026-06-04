import type { DependencyManager, Module } from '../../plugins'
import { W3cV2JwtCredentialService } from './jwt-vc'
import { SignatureSuiteRegistry } from './linked-data-proofs/SignatureSuiteRegistry'
import { W3cV2CredentialRepository } from './repository/W3cV2CredentialRepository'
import { W3cV2SdJwtCredentialService } from './sd-jwt-vc'
import { W3cV2CredentialService } from './W3cV2CredentialService'
import { W3cV2CredentialsApi } from './W3cV2CredentialsApi'

export interface W3cV2CredentialsModuleConfigOptions {
  // Reserved for future VC2 module-level options.
}

/**
 * @public
 */
export class W3cV2CredentialsModule implements Module {
  public readonly api = W3cV2CredentialsApi
  public readonly options: Readonly<W3cV2CredentialsModuleConfigOptions>

  public constructor(options?: W3cV2CredentialsModuleConfigOptions) {
    this.options = options ?? {}
  }

  public register(dependencyManager: DependencyManager) {
    dependencyManager.registerSingleton(W3cV2CredentialService)
    dependencyManager.registerSingleton(W3cV2JwtCredentialService)
    dependencyManager.registerSingleton(W3cV2SdJwtCredentialService)
    dependencyManager.registerSingleton(W3cV2CredentialRepository)
    dependencyManager.registerSingleton(SignatureSuiteRegistry)
  }
}
