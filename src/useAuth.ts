import type { ComputedRef, Ref } from 'vue'
import { computed, ref, watch } from 'vue'
import axios, { AxiosError } from 'axios'

enum GrantType {
  PASSWORD = 'password',
  REFRESH_TOKEN = 'refresh_token',
}

interface OAuth {
  accessToken: string
  refreshToken: string
  tokenType: string
  expiresIn: number
}

interface UseAuth<T> {
  isAuthenticated: ComputedRef<boolean>
  user: Ref<T | null>
  signIn: (email: string, password: string) => Promise<void>
  signOut: () => void
  invalidateToken: () => Promise<void>
  getUser: () => Promise<T>
}

interface Options {
  clientId: string
  clientSecret: string
  baseURL: string
}

const user = ref<unknown | null>(null)
const isAuthenticated = computed(() => user.value !== null)

const oAuth = ref<OAuth | null>(localStorage.getItem('oAuth') !== undefined
  ? JSON.parse(localStorage.getItem('oAuth') as string)
  : null,
)

watch((oAuth), (oAuth) => {
  if (oAuth !== null)
    axios.defaults.headers.common.Authorization = `Bearer ${oAuth.accessToken}`

  localStorage.setItem('oAuth', JSON.stringify(oAuth))
}, { immediate: true })

export default <T>({ baseURL, clientId, clientSecret }: Options): UseAuth<T> => {
  const signIn = async (email: string, password: string): Promise<void> => {
    const { data } = await axios({
      url: '/oauth/token',
      method: 'POST',
      data: {
        password,
        username: email,
        grantType: GrantType.PASSWORD,
        clientId,
        clientSecret,
      },
      baseURL,
    })

    oAuth.value = data
  }

  const refreshToken = async (): Promise<void> => {
    const { data } = await axios({
      url: '/oauth/token',
      method: 'POST',
      data: {
        grantType: GrantType.REFRESH_TOKEN,
        clientId,
        clientSecret,
        refreshToken: oAuth.value?.refreshToken,
      },
      baseURL,
    })

    oAuth.value = data
  }

  const invalidateToken = async (): Promise<void> => {
    await axios({
      url: `/oauth/invalidate?token=${oAuth.value?.accessToken as string}`,
      baseURL,
    })
  }

  const signOut = (): void => {
    oAuth.value = null
    user.value = null
    axios.defaults.headers.common.Authorization = ''
  }

  const getUser = async (): Promise<T> => {
    if (oAuth.value === null)
      throw new Error('Not logged in')

    const { data } = await axios.get('/users/me')

    user.value = data

    return data
  }

  axios.interceptors.response.use(
    r => r,
    async (e) => {
      if (e instanceof AxiosError) {
        const status = e.response?.status ?? null

        if (status === 401 && oAuth.value !== null) {
          try {
            await refreshToken()

            return await axios.request({
              ...e.config,
              headers: {
                Authorization: `Bearer ${oAuth.value.accessToken}`,
              },
            })
          }
          catch (_) {
            return await Promise.reject(e)
          }
        }
      }

      return await Promise.reject(e)
    })

  return {
    isAuthenticated,
    user: user as Ref<T | null>,
    signIn,
    signOut,
    invalidateToken,
    getUser,
  }
}
