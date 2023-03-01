type ConnectParams = {
  uxMode: 'popup' | 'redirect',
  redirectUrl: string,
}

type CallOptions = {
  uxMode?: 'popup' | 'redirect',
  redirectUrl?: string,
}

export class ChomWallet {
  private static CLIENT_ID: string
  private static CLIENT_SECRET: string
  private static API_URL: string

  public address: string
  public accountId: string
  private accessToken: string
  private expiredAt: number

  static init(clientId: string, clientSecret: string, env: 'dev' | 'prod' = 'dev'): void {
    ChomWallet.CLIENT_ID = clientId
    ChomWallet.CLIENT_SECRET = clientSecret

    if (env === 'prod') {
      ChomWallet.API_URL = 'https://chom-walet.chomchob.com'
    } else {
      ChomWallet.API_URL = 'https://dev-chom-walet.chomchob.com'
    }
  }

  constructor(address: string, accountId: string, accessToken: string, expiredAt: number) {
    this.address = address
    this.accountId = accountId
    this.accessToken = accessToken
    this.expiredAt = expiredAt
  }

  private static async  requestLoginUrl(uxMode: 'popup' | 'redirect'): Promise<string> {
    if (!ChomWallet.CLIENT_ID || !ChomWallet.CLIENT_SECRET) {
      throw new Error('Client not initialized')
    }

    // axios.post('//chomwallet-api.chomchob.com', { CLIENT_ID, CLIENT_SECRET, uxMode})
    const loginUrl = ''
    return loginUrl
  }
  static async  connect(options: CallOptions): Promise<ChomWallet> {
    if (!ChomWallet.CLIENT_ID || !ChomWallet.CLIENT_SECRET) {
      throw new Error('Client not initialized')
    }

    if (options.uxMode === 'popup') {
      const loginUrl = await this.requestLoginUrl(options.uxMode)
      
      // todo: open login in popup and listening access_token
      const { accessToken, expiredAt } = { accessToken: '', expiredAt: 100000 }

      // todo: query user profile
      const { address, accountId } = { address: '', accountId: '' }

      return new ChomWallet(address, accountId, accessToken, expiredAt)
    } else {
      // todo: redirect flow
      return new ChomWallet('', '', '', 0)
    }
  }

  async signMessage(msg: string, options: CallOptions = {}): Promise<string> {
    return 'sig'
  }

  async signTypedData(options: CallOptions = {}): Promise<string> {
    return 'sig'
  }

  
}