declare module ChomWalletDataTypes {

  export interface ConnectParams{
    uxMode: 'popup' | 'redirect'
    redirectUrl: string
  }
  
  export interface CallOptions {
    ux_mode: 'popup' | 'redirect'
    timestamp?: number
    signature?: string
    redirect_uri?: string
  }

  export interface WalletList {
    name: string
    address: string
  }

  export interface WalletResponse {
    account_id: string
    email: string
    wallet_list: WalletList[]
    register_status: string
  }

  export interface SignMessageParams {
    message: string
    description: string
    ux_mode: 'popup' | 'redirect'
    redirect_uri?: string
  }

  export interface SignTypedParams {
      wallet_number: number
      domain: {
        chainId: string
      }
      type: {
        name: string
        type: string
      }
      data: {
        to: string
      }
      ux_mode: string
      redirect_uri?: string
  }

  export interface SignTransactionParams {
    wallet_number: number
    to: string
    chain_id: number
    ux_mode: 'popup' | 'redirect'
    redirect_uri?: string
  }
}

export default ChomWalletDataTypes