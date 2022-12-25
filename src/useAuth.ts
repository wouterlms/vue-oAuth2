import { computed, ref, watch } from 'vue'
import type { AxiosResponse } from 'axios'
import axios, { AxiosError } from 'axios'

import type { ComputedRef, Ref } from 'vue'

export interface UseAuth<T> {
  // Whether `user` is not `null`
  isAuthenticated: ComputedRef<boolean>
  // The user object
  user: Ref<T | null>
  // Sign in with email and password
  signIn: (email: string, password: string) => Promise<void>
  // Sign out, sets `user` to null and clears the `oAuth` object in localStorage
  signOut: () => void
  // Revoke the current access token
  revoke: () => Promise<void>
  // Get the user object from the API
  getUser: () => Promise<T>
}

export interface OAuth {
  accessToken: string
  refreshToken: string
  tokenType: string
  expiresIn: number
  expiresAt: number
}

enum GrantType {
  PASSWORD = 'password',
  REFRESH_TOKEN = 'refresh_token',
}

interface Options {
  clientId: string
  clientSecret: string
  baseURL: string
  endpoints: {
    userInfo: string
    revoke: string | ((accessToken: string) => string)
  }
  extraParams?: Record<string, string>
  autoRefreshAccessToken?: {
    preFetchInMs: number
  } | boolean
  onRefreshTokenFailed?: () => void
}

const user = ref<unknown | null>(null)
const isAuthenticated = computed(() => user.value !== null)

let refreshTokenTimeout: ReturnType<typeof setTimeout> | null = null
let isRefreshingToken = false
let failedRequestsQueue: Array<(accessToken: string) => Promise<AxiosResponse>> = []

const oAuth = ref<OAuth | null>(localStorage.getItem('oAuth') !== undefined
  ? JSON.parse(localStorage.getItem('oAuth') as string)
  : null,
)

watch((oAuth), (oAuth) => {
  axios.defaults.headers.common.Authorization = oAuth === null
    ? ''
    : `Bearer ${oAuth.accessToken}`

  localStorage.setItem('oAuth', JSON.stringify(oAuth))
}, { immediate: true })

export default <T>(options: Options): UseAuth<T> => {
  const {
    clientId,
    clientSecret,
    baseURL,
    endpoints,
    extraParams,
    autoRefreshAccessToken,
    onRefreshTokenFailed,
  } = options

  const shouldRefreshToken = autoRefreshAccessToken === true
    || typeof autoRefreshAccessToken === 'object'

  const refreshTokenTimeoutInMs = typeof autoRefreshAccessToken === 'object'
    ? autoRefreshAccessToken.preFetchInMs
    : 60 * 1000

  const setRefreshTokenTimeout = (): void => {
    if (refreshTokenTimeout !== null)
      clearTimeout(refreshTokenTimeout)

    if (oAuth.value === null)
      throw new Error('Attempted to call `setRefreshTokenTimeout()` when `oAuth` is null')

    const timeoutInMs = oAuth.value.expiresAt - Date.now() - refreshTokenTimeoutInMs

    if (timeoutInMs > 0) {
      refreshTokenTimeout = setTimeout(() => {
        // eslint-disable-next-line @typescript-eslint/no-use-before-define
        refreshToken()
      }, timeoutInMs)
    }
    else {
      // eslint-disable-next-line @typescript-eslint/no-use-before-define
      refreshToken()
    }
  }

  const signIn = async (email: string, password: string): Promise<void> => {
    const { data } = await axios({
      ...(extraParams ?? {}),
      url: '/oauth/token',
      method: 'POST',
      data: new URLSearchParams({
        password,
        username: email,
        grant_type: GrantType.PASSWORD,
        client_id: clientId,
        client_secret: clientSecret,
      }),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      baseURL,
    })

    oAuth.value = {
      ...oAuth.value,
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      tokenType: data.token_type,
      expiresIn: data.expires_in,
      expiresAt: Date.now() + data.expires_in * 1000,
    }

    if (shouldRefreshToken)
      setRefreshTokenTimeout()
  }

  const refreshToken = async (): Promise<void> => {
    if (oAuth.value === null)
      throw new Error('Not logged in')

    try {
      const { data } = await axios({
        ...(extraParams ?? {}),
        url: '/oauth/token',
        method: 'POST',
        data: new URLSearchParams({
          grant_type: GrantType.REFRESH_TOKEN,
          client_id: clientId,
          client_secret: clientSecret,
          refresh_token: oAuth.value.refreshToken,
        }),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        baseURL,
      })

      oAuth.value = {
        ...oAuth.value,
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        tokenType: data.token_type,
        expiresIn: data.expires_in,
        expiresAt: Date.now() + data.expires_in * 1000,
      }

      if (shouldRefreshToken)
        setRefreshTokenTimeout()
    }
    catch {
      oAuth.value = null
      onRefreshTokenFailed?.()
    }
  }

  const signOut = () => {
    oAuth.value = null
    user.value = null

    if (refreshTokenTimeout !== null)
      clearTimeout(refreshTokenTimeout)
  }

  const revoke = async () => {
    if (oAuth.value === null)
      throw new Error('Not logged in')

    const { revoke: revokeEndpoint } = endpoints

    const endpoint = typeof revokeEndpoint === 'function'
      ? revokeEndpoint(oAuth.value.accessToken)
      : revokeEndpoint

    await axios.post(endpoint)
  }

  const getUser = async (): Promise<T> => {
    if (oAuth.value === null)
      throw new Error('Not logged in')

    const { data } = await axios.get(endpoints.userInfo, {
      baseURL,
    })

    user.value = data

    return data
  }

  const processQueue = async (accessToken: string): Promise<void> => {
    failedRequestsQueue.forEach(request => request(accessToken))
  }

  axios.interceptors.response.use(
    req => req,
    async (err) => {
      if (!(err instanceof AxiosError))
        return await Promise.reject(err)

      const status = err.response?.status ?? null
      const url = err.config?.url ?? null

      if (status !== 401 || oAuth.value === null || url === '/oauth/token')
        return await Promise.reject(err)

      const originalHeaders = err.config?.headers ?? {}

      failedRequestsQueue.push((accessToken: string) => axios.request({
        ...err.config,
        headers: {
          ...originalHeaders,
          Authorization: `Bearer ${accessToken}`,
        },
      }))

      if (!isRefreshingToken) {
        isRefreshingToken = true

        try {
          await refreshToken()
          await processQueue(oAuth.value.accessToken)
        }
        catch {}

        failedRequestsQueue = []
        isRefreshingToken = false
      }

      return await Promise.reject(err)
    })

  if (oAuth.value !== null && shouldRefreshToken)
    setRefreshTokenTimeout()

  return {
    user: user as Ref<T | null>,
    isAuthenticated,
    signIn,
    signOut,
    revoke,
    getUser,
  }
}
