import { type ApiModule, type DependencyManager, DidsModuleConfig } from '@credo-ts/core'
import { WebVhDidRegistrar, WebVhDidResolver } from './dids'
import { WebVhApi } from './WebVhApi'

export class WebVhModule implements ApiModule {
  public readonly api = WebVhApi

  /**
   * Adds a WebVH resolver and registrar to the DidsModule when none is configured. The dependency manager registers
   * the API from `api`.
   *
   * @param dependencyManager Agent dependency manager with the DID module configuration.
   */
  public register(dependencyManager: DependencyManager) {
    // Preserve an explicitly configured WebVH resolver.
    const didsModuleConfig = dependencyManager.resolve(DidsModuleConfig)
    if (!didsModuleConfig.resolvers.some((resolver) => resolver instanceof WebVhDidResolver)) {
      didsModuleConfig.addResolver(new WebVhDidResolver())
    }
    if (!didsModuleConfig.registrars.some((registrar) => registrar.supportedMethods.includes('webvh'))) {
      didsModuleConfig.addRegistrar(new WebVhDidRegistrar())
    }
  }
}
