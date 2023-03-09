declare module ChomWalletDataTypes {

  export interface ConnectParams{
    uxMode: 'popup' | 'redirect'
    redirectUrl: string
  }
  
  export interface CallOptions {
    ux_mode: 'popup' | 'redirect'
    timestamp: number
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

}

export default ChomWalletDataTypes