import axios from "axios"
import jwt from "jsonwebtoken"
import Cookies from "js-cookie"
import ChomWalletDataTypes from "../src/types"
import CryptoJS from "crypto-js"

// type ConnectParams = {
//   uxMode: 'popup' | 'redirect',
//   redirectUrl: string,
// }

// type CallOptions = {
//   ux_mode: 'popup' | 'redirect',
//   timestamp: number,
//   signature?: string,
//   redirect_uri?: string,
// }

export class ChomWallet {
  private static CLIENT_ID: string
  private static CLIENT_SECRET: string
  private static API_URL: string

  public address: string
  public accountId: string
  private accessToken: string
  private expiredAt: number

  static init(
    clientId: string,
    clientSecret: string,
    env: "dev" | "prod" = "dev"
  ): void {
    ChomWallet.CLIENT_ID = clientId
    ChomWallet.CLIENT_SECRET = clientSecret

    if (env === "prod") {
      ChomWallet.API_URL = "https://chom-walet.chomchob.com"
    } else {
      ChomWallet.API_URL = "https://dev-chom-walet.chomchob.com"
    }
  }

  constructor(
    address: string,
    accountId: string,
    accessToken: string,
    expiredAt: number
  ) {
    var urlParams = new URL(window.location.href);
    var token = urlParams.searchParams.get('token');
    if (token) {
      this.accessToken = token
      this.setTokentoStorage(token)
      window.history.replaceState({}, document.title, window.location.pathname)
    }
    document.addEventListener('token', (event: any) =>{
      if (event.data.token) {
        this.accessToken = event.data.token
        this.setTokentoStorage(event.data.token)
      }
    })
    this.address = address
    this.accountId = accountId
    this.accessToken = accessToken
    this.expiredAt = expiredAt
  }

  static async getUserInfo(token: string) {
    if (!ChomWallet.CLIENT_ID || !ChomWallet.CLIENT_SECRET) {
      throw new Error("Client not initialized")
    }

    try {
      const response: any = await axios(`${ChomWallet.API_URL}/v1/app/login`, {
        method: "GET",
        headers: {
          Authorization: token
        }
      })

      return response.data
    } catch (error: any) {
      throw new Error(error)
    }
  }

  static async requestLogin(
    options: ChomWalletDataTypes.CallOptions
  ): Promise<string> {
    if (!ChomWallet.CLIENT_ID || !ChomWallet.CLIENT_SECRET) {
      throw new Error("Client not initialized")
    }

    const payload: ChomWalletDataTypes.CallOptions = {
      ux_mode: options.ux_mode,
      timestamp: new Date().getTime()
    }

    if (options.redirect_uri) {
      payload.redirect_uri = options.redirect_uri
    }

    const token: string = jwt.sign(payload, ChomWallet.CLIENT_SECRET, {
      algorithm: "HS512",
      noTimestamp: true
    })

    if (token) {
      payload.signature = token
    }

    try {
      const response: any = await axios(`${ChomWallet.API_URL}/v1/app/login`, {
        method: "GET",
        headers: {
          "client-id": ChomWallet.CLIENT_ID,
          Origin: window.location.hostname
        },
        params: payload
      })

      if (options.ux_mode === "popup") {
        window.open(
          response.data.url,
          "_blank",
          "location=yes,scrollbars=yes,status=yes,width=400,height=400"
        )
      } else {
        window.location.href = response.data.url
      }

      return response.data.url
    } catch (error: any) {
      throw new Error(error)
    }
  }

  static async connect(
    options: ChomWalletDataTypes.CallOptions
  ): Promise<ChomWallet> {
    if (!ChomWallet.CLIENT_ID || !ChomWallet.CLIENT_SECRET) {
      throw new Error("Client not initialized")
    }

    const accessToken: string | null = await this.getTokenFromStorage()
    if (accessToken) {
      return new ChomWallet("test", "test", "test", 0)
    } else {
      const loginUrl = await this.requestLogin(options)

      if (loginUrl && options.ux_mode === "popup") {
        window.open(
          loginUrl,
          "_blank",
          "location=yes,scrollbars=yes,status=yes,width=500,height=400"
        )
      } else {
        window.location.href = loginUrl
      }

      return new ChomWallet("", "", "", 0)
    }
  }

  async signMessage(
    msg: string,
    options: ChomWalletDataTypes.CallOptions
  ): Promise<string> {
    return "sig"
  }

  async signTypedData(
    options: ChomWalletDataTypes.CallOptions
  ): Promise<string> {
    return "sig"
  }

  async encryptData(data: any): Promise<string> {
    let encryptedData: string = CryptoJS.AES.encrypt(data, ChomWallet.CLIENT_SECRET).toString()
    return encryptedData
  }

  private static async decryptData(data: any): Promise<string> {
    let decryptedData: string = CryptoJS.AES.decrypt(data, ChomWallet.CLIENT_SECRET).toString(
      CryptoJS.enc.Utf8
    )
    return decryptedData
  }

  async setTokentoStorage(token: string) {
    const dataEncrypt: string = await this.encryptData(token)
    Cookies.set('t', dataEncrypt)
  }

  private static async getTokenFromStorage(): Promise<string | null> {
    const tokenFromStorage: string | undefined = Cookies.get('t')
    if (tokenFromStorage) {
      const dataDecrypt: string = await this.decryptData(tokenFromStorage)
      const base64Url: string = dataDecrypt.split('.')[1]
      const base64: string = base64Url.replace(/-/g, '+').replace(/_/g, '/')
      const jsonPayload: string = decodeURIComponent(window.atob(base64).split('').map(function(c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
      }).join(''))
      const jsonData = JSON.parse(jsonPayload)
      if (jsonData.exp > new Date().getTime()) {
        return dataDecrypt
      } else {
        return null
      }
    } else {
      return null
    }
  }
}
