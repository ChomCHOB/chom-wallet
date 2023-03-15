import axios from "axios"
import Cookies from "js-cookie"
import ChomWalletDataTypes from "../src/types"
import CryptoJS from "crypto-js"
import * as jose from 'jose'

export class ChomWallet {
  private static CLIENT_ID: string
  private static CLIENT_SECRET: string
  private static API_URL: string

  public address: Array<{[key: string]: any}>
  public accountId: string

  static init(
    clientId: string,
    clientSecret: string,
    env: "dev" | "prod" = "dev"
  ): void {
    ChomWallet.CLIENT_ID = clientId
    ChomWallet.CLIENT_SECRET = clientSecret
    
    if (env === "prod") {
      ChomWallet.API_URL = "https://chom-wallet.chomchob.com"
    } else {
      ChomWallet.API_URL = "https://dev-chom-wallet.chomchob.com"
    }

    const urlParams: URL = new URL(window.location.href);
    var token: string | null = urlParams.searchParams.get('cw_tk');
    
    if (token) {
      this.setTokentoStorage(token)
      window.history.replaceState({}, document.title, window.location.pathname)
    }

    window.addEventListener('cw_tk', (event: any) =>{
      if (event.data.token) {
        this.setTokentoStorage(event.data.token)
      }
    })
  }

  constructor(
    address: Array<{[key: string]: any}>,
    accountId: string,
  ) {
    this.address = address
    this.accountId = accountId
  }

  static async getUserInfo() {
    const accessToken: string | null = await this.getTokenFromStorage()
    if (!ChomWallet.CLIENT_ID || !ChomWallet.CLIENT_SECRET || !accessToken) {
      throw new Error("Client not initialized")
    }
    const deviceId = await this.getDeviceId()
    try {
      const response = await axios(`${ChomWallet.API_URL}/v1/app/login`, {
        method: 'GET',
        headers: {
          'Authorization': accessToken,
          'device-id': deviceId
        }
      })
      return new ChomWallet(response.data.account_id, response.data.wallet_list)
    } catch (error: any) {
      throw new Error(error)
    }
  }

  static async connect(
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

    const secret = new TextEncoder().encode(
      ChomWallet.CLIENT_SECRET
    )
    const alg = 'HS512'
    const typ = 'JWT'

    const token: string = await new jose.SignJWT({ ...payload })
    .setProtectedHeader({ alg, typ })
    .sign(secret)

    if (token) {
      payload.signature = token
    }

    try {
      const response: any = await axios(`${ChomWallet.API_URL}/v1/app/login`, {
        method: "GET",
        headers: {
          'client-id': ChomWallet.CLIENT_ID
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

  static async signMessage(
    options: ChomWalletDataTypes.SignMessageParams
  ): Promise<string> {
    const accessToken: string | null = await this.getTokenFromStorage()
    if (!ChomWallet.CLIENT_ID || !ChomWallet.CLIENT_SECRET || !accessToken) {
      throw new Error("Client not initialized")
    }
    const deviceId = await this.getDeviceId()

    if (options.ux_mode === 'popup') {
      delete options.redirect_uri
    }

    try {
      const response: any = await axios(`${ChomWallet.API_URL}/v1/app/sign/message`, {
        method: "POST",
        headers: {
          'Authorization': accessToken,
          'device-id': deviceId
        },
        data: options
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

  static async signTypedData(
    options: ChomWalletDataTypes.SignTypedParams
  ): Promise<string> {
    const accessToken: string | null = await this.getTokenFromStorage()
    if (!ChomWallet.CLIENT_ID || !ChomWallet.CLIENT_SECRET || !accessToken) {
      throw new Error("Client not initialized")
    }
    const deviceId = await this.getDeviceId()

    if (options.ux_mode === 'popup') {
      delete options.redirect_uri
    }

    try {
      const response: any = await axios(`${ChomWallet.API_URL}/v1/app/request/sign/typed-data`, {
        method: "POST",
        headers: {
          'Authorization': accessToken,
          'device-id': deviceId
        },
        data: options
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

  static async signTransaction(
    options: ChomWalletDataTypes.SignTransactionParams
  ): Promise<string> {
    const accessToken: string | null = await this.getTokenFromStorage()
    if (!ChomWallet.CLIENT_ID || !ChomWallet.CLIENT_SECRET || !accessToken) {
      throw new Error("Client not initialized")
    }
    const deviceId = await this.getDeviceId()

    if (options.ux_mode === 'popup') {
      delete options.redirect_uri
    }

    try {
      const response: any = await axios(`${ChomWallet.API_URL}/v1/app/request/sign/typed-data`, {
        method: "POST",
        headers: {
          'Authorization': accessToken,
          'device-id': deviceId
        },
        data: options
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

  private static async encryptData(data: any): Promise<string> {
    let encryptedData: string = CryptoJS.AES.encrypt(data, ChomWallet.CLIENT_SECRET).toString()
    return encryptedData
  }

  private static async decryptData(data: any): Promise<string> {
    let decryptedData: string = CryptoJS.AES.decrypt(data, ChomWallet.CLIENT_SECRET).toString(
      CryptoJS.enc.Utf8
    )
    return decryptedData
  }

  private static async setTokentoStorage(token: string) {
    alert('token')
    const dataEncrypt: string = await this.encryptData(token)
    Cookies.set('cw_tk', dataEncrypt)
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

  private static async getDeviceId(): Promise<string> {
    return (`${1e7}-${1e3}-${4e3}-${8e3}-${1e11}`).replace(/[018]/g, (c: any) =>
        (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
    )
  }
}
