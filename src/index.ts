import axios from 'axios'
import jwt from 'jsonwebtoken'
import Cookies from 'js-cookie'


type ConnectParams = {
  uxMode: 'popup' | 'redirect',
  redirectUrl: string,
}

type CallOptions = {
  ux_mode: 'popup' | 'redirect',
  signature?: string,
  redirect_uri?: string,
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

  private static async requestLoginUrl(options: CallOptions): Promise<string> {
    if (!ChomWallet.CLIENT_ID || !ChomWallet.CLIENT_SECRET) {
      throw new Error('Client not initialized')
    }

    const payload: CallOptions = {
      ux_mode: options.ux_mode
    }

    if (options.redirect_uri) {
      payload.redirect_uri = options.redirect_uri
    }

    const token: string = jwt.sign(payload, ChomWallet.CLIENT_SECRET, {
      algorithm: 'HS512',
      noTimestamp: true,
    })

    if (token) {
      payload.signature = token
    }

    const loginUrl: any = await axios(`${ChomWallet.API_URL}/v1/app/login`, {
      method: 'GET',
      headers: {
        "client-id": ChomWallet.CLIENT_ID,
        Origin: window.location.hostname
      },
      params: payload
    })

    return loginUrl
  }

  static async connect(options: CallOptions): Promise<ChomWallet> {
    if (!ChomWallet.CLIENT_ID || !ChomWallet.CLIENT_SECRET) {
      throw new Error('Client not initialized')
    }

    
    // if (options.uxMode === 'popup') {
    //   const loginUrl = await this.requestLoginUrl(options.uxMode)
      
    //   // todo: open login in popup and listening access_token
    //   const { accessToken, expiredAt } = { accessToken: '', expiredAt: 100000 }

    //   // todo: query user profile
    //   const { address, accountId } = { address: '', accountId: '' }

    //   return new ChomWallet(address, accountId, accessToken, expiredAt)
    // } else {
    //   // todo: redirect flow
    //   return new ChomWallet('', '', '', 0)
    // }

    // if () {
    //   return new ChomWallet('', '', '', 0)
    // } else {
    //   return new ChomWallet('', '', '', 0)
    // }

    const accessToken: string = Cookies.get('u_info') || ''
    if (accessToken) {
      return new ChomWallet('', '', '', 0)
    } else {
      const loginUrl = await this.requestLoginUrl(options)

      if (loginUrl && options.ux_mode === 'popup') {
        window.open(loginUrl, '_blank', 'location=yes,scrollbars=yes,status=yes,width=400,height=400')
      } else {
        window.location.href = loginUrl
      }
      return new ChomWallet('', '', '', 0)
    }
  }

  

  async signMessage(msg: string, options: CallOptions): Promise<string> {
    return 'sig'
  }

  async signTypedData(options: CallOptions): Promise<string> {
    return 'sig'
  }

  
}