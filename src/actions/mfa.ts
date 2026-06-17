import { type Address, encodeFunctionData, type Hex, padHex, toHex } from 'viem'
import {
  getModuleInstallationCalls,
  getModuleUninstallationCalls,
} from '../accounts'
import {
  getMultiFactorSubValidatorData,
  getMultiFactorValidator,
  getValidator,
  MULTI_FACTOR_VALIDATOR_ADDRESS,
} from '../modules/validators/core'
import type {
  CalldataInput,
  LazyCallInput,
  OwnableValidatorConfig,
  WebauthnValidatorConfig,
} from '../types'

type MultiFactorActionOptions = {
  module?: Address
  accountAddress?: Address
}

function getMultiFactorAddress(options?: MultiFactorActionOptions): Address {
  return options?.module ?? MULTI_FACTOR_VALIDATOR_ADDRESS
}

/**
 * Enable multi-factor authentication
 * @param validators List of validators to use
 * @param threshold Threshold for the validators
 * @returns Calls to enable multi-factor authentication
 */
function enable(
  validators: (OwnableValidatorConfig | WebauthnValidatorConfig | null)[],
  threshold = 1,
  options?: MultiFactorActionOptions,
): LazyCallInput {
  return {
    async resolve({ config, accountAddress }) {
      const module = getMultiFactorValidator(
        threshold,
        validators,
        options?.module,
        options?.accountAddress ?? accountAddress,
      )
      return getModuleInstallationCalls(config, module)
    },
  }
}

/**
 * Change the multi-factor threshold
 * @param newThreshold New threshold
 * @returns Call to change the threshold
 */
function changeThreshold(
  newThreshold: number,
  options?: MultiFactorActionOptions,
): CalldataInput {
  return {
    to: getMultiFactorAddress(options),
    value: 0n,
    data: encodeFunctionData({
      abi: [
        {
          inputs: [{ internalType: 'uint8', name: 'threshold', type: 'uint8' }],
          name: 'setThreshold',
          outputs: [],
          stateMutability: 'nonpayable',
          type: 'function',
        },
      ],
      functionName: 'setThreshold',
      args: [newThreshold],
    }),
  }
}

/**
 * Disable multi-factor authentication
 * @param rhinestoneAccount Account to disable multi-factor authentication on
 * @returns Calls to disable multi-factor authentication
 */
function disable(options?: MultiFactorActionOptions): LazyCallInput {
  const module = getMultiFactorValidator(1, [], options?.module)
  return {
    async resolve({ config }) {
      return getModuleUninstallationCalls(config, module)
    },
  }
}

/**
 * Set a sub-validator (multi-factor)
 * @param id Validator ID
 * @param validator Validator module
 * @returns Call to set the sub-validator
 */
function setSubValidator(
  id: Hex | number,
  validator: OwnableValidatorConfig,
  options?: MultiFactorActionOptions,
): CalldataInput
function setSubValidator(
  id: Hex | number,
  validator: WebauthnValidatorConfig,
  options: MultiFactorActionOptions & { accountAddress: Address },
): CalldataInput
function setSubValidator(
  id: Hex | number,
  validator: WebauthnValidatorConfig,
  options?: MultiFactorActionOptions,
): LazyCallInput
function setSubValidator(
  id: Hex | number,
  validator: OwnableValidatorConfig | WebauthnValidatorConfig,
  options?: MultiFactorActionOptions,
): CalldataInput | LazyCallInput {
  const validatorId = padHex(toHex(id), { size: 12 })
  const validatorModule = getValidator(validator)

  const buildCall = (accountAddress?: Address): CalldataInput => {
    const newValidatorData = getMultiFactorSubValidatorData(
      validator,
      accountAddress,
    )
    return {
      to: getMultiFactorAddress(options),
      value: 0n,
      data: encodeFunctionData({
        abi: [
          {
            type: 'function',
            name: 'setValidator',
            inputs: [
              {
                type: 'address',
                name: 'validatorAddress',
              },
              {
                type: 'bytes12',
                name: 'validatorId',
              },
              {
                type: 'bytes',
                name: 'newValidatorData',
              },
            ],
          },
        ],
        functionName: 'setValidator',
        args: [validatorModule.address, validatorId, newValidatorData],
      }),
    }
  }

  if (validator.type !== 'passkey' || options?.accountAddress) {
    return buildCall(options?.accountAddress)
  }

  return {
    async resolve({ accountAddress }) {
      return buildCall(accountAddress)
    },
  }
}

/**
 * Remove a sub-validator (multi-factor)
 * @param id Validator ID
 * @param validator Validator module
 * @returns Call to remove the sub-validator
 */
function removeSubValidator(
  id: Hex | number,
  validator: OwnableValidatorConfig | WebauthnValidatorConfig,
  options?: MultiFactorActionOptions,
): CalldataInput {
  const validatorId = padHex(toHex(id), { size: 12 })
  const validatorModule = getValidator(validator)
  return {
    to: getMultiFactorAddress(options),
    value: 0n,
    data: encodeFunctionData({
      abi: [
        {
          type: 'function',
          name: 'removeValidator',
          inputs: [
            {
              type: 'address',
              name: 'validatorAddress',
            },
            {
              type: 'bytes12',
              name: 'validatorId',
            },
          ],
        },
      ],
      functionName: 'removeValidator',
      args: [validatorModule.address, validatorId],
    }),
  }
}

export { enable, changeThreshold, disable, setSubValidator, removeSubValidator }
