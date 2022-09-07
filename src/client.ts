import jwt from "jsonwebtoken"
import { DateTime } from "luxon"
import { signMessageWithEthereumPrivateKey } from "./signing"
import { Account, Administrator, Asset, AssetBalance, AssetPrice, AssetSettings, AssetSource, Client, FeeCalculation, FundMetricsEntry, InvestorPortalAccessLogEntry, InvestorPortalOptions, ModificationLogEntry, UnitHoldersRegisterEntry } from "@blockchain-assets/data-types"

const ENDPOINTS = {
    VERIFY_SIGNATURE: "/v1/token/verify_signature",
    EMAIL_CHALLENGE: "/v1/token/email_challenge",
    VERIFY_EMAIL: "/v1/token/verify_email",
    ADMINISTRATORS: "/v1/administrators",
    ADMINISTRATOR: (adminId: string | number) => `/v1/administrators/${adminId}`,
    ASSETS: "/v1/assets",
    ASSET_SETTINGS: "/v1/assets/settings",
    SETTINGS_FOR_ASSET: (assetName: string) => `/v1/assets/settings/${assetName}`,
    PRICES: "/v1/assets/prices",
    BALANCES: "/v1/assets/balances",
    SOURCES: "/v1/assets/sources",
    UNIT_HOLDERS_REGISTER: "/v1/unit_holders_register",
    ACCOUNTS: "/v1/accounts",
    ACCOUNT: (accountId: string | number) => `/v1/accounts/${accountId}`,
    CLIENTS_FOR_ACCOUNT: (accountId: string | number) => `/v1/accounts/${accountId}/registered_clients`,
    CLIENTS: "/v1/clients",
    CLIENT: (clientId: string | number) => `/v1/clients/${clientId}`,
    ACCOUNTS_FOR_CLIENT: (clientId: string | number) => `/v1/clients/${clientId}/registered_accounts`,
    HISTORICAL_FUND_METRICS: "/v1/fund_metrics/historical",
    RECENT_FUND_METRICS: "/v1/fund_metrics/recent",
    INVESTOR_PORTAL_ACCESS_LOG: "/v1/investor_portal/access_log",
    INVESTOR_PORTAL_OPTIONS: "/v1/investor_portal/options",
    MODIFICATION_EVENT_LOG: "/v1/audit/modification_event_log",
    CALCULATE_FEES: "/v1/fees/calculate"
}

type FetchOptions = {
    method: string
    auth?: boolean
    queryParams?: Record<string, any>
    payload?: Record<string, any>
    signed?: boolean
}

type APIResponse = {
    status: number,
    body: Record<string, any>
}

type StatusResponse = {
    status: number
}

type TokenResponse = {
    status: number,
    token?: string
}

type DataResponse<T> = {
    status: number,
    data?: T
}

const toISO = (date: string | Date | DateTime): string => {
    if (date instanceof Date) {
        return date.toISOString()
    }
    else if (date instanceof DateTime) {
        return date.toUTC().toISO()
    }
    else {
        const dateTime = DateTime.fromJSDate(new Date(date))
        if (dateTime.isValid) {
            return dateTime.toUTC().toISO()
        }
        else {
            throw new Error(`The provided value could not be parsed to a valid date: '${date}'`)
        }
    }
}

export class BCA_API_Client {
    private apiUrl: string
    private authToken?: string
    private signingKey?: string
    private signingFunction?: Function
    private autoRequestNewAuthToken: boolean

    constructor(apiUrl: string, { authToken, signingKey, signingFunction }: { authToken?: string, signingKey?: string, signingFunction?: Function }) {
        this.apiUrl = apiUrl
        this.authToken = authToken
        this.signingKey = signingKey
        this.signingFunction = signingFunction

        this.autoRequestNewAuthToken = !!signingKey
    }

    private getAuthToken = async (): Promise<string | undefined> => {
        // Check if valid auth token is cached.
        if (this.authToken) {
            const decoded = jwt.decode(this.authToken, { json: true })
            if (decoded && decoded.exp && DateTime.fromSeconds(decoded.exp) > DateTime.now()) {
                return this.authToken
            }
            else {
                this.authToken = undefined
            }
        }

        // If possible, request a new token.
        if (this.autoRequestNewAuthToken) {
            const token = (await this.submitSignedAuthRequest()).token
            if (!token) {
                throw new Error("Failed to obtain new auth token.")
            }
            else {
                this.authToken = token
                return this.authToken
            }
        }
    }

    private signMessage = async (message: string): Promise<string> => {
        if (this.signingFunction) {
            return await this.signingFunction(message)
        }
        else if (this.signingKey) {
            return await signMessageWithEthereumPrivateKey(message, this.signingKey)
        }
        else {
            throw new Error("Cannot sign message - no signing function or signing key supplied.")
        }
    }

    private fetchBase = async (endpoint: string, fetchOptions: FetchOptions): Promise<APIResponse> => {
        const { method, auth, queryParams, payload, signed } = fetchOptions
        const bodyString = signed ? JSON.stringify({ endpoint: `${method} ${endpoint}`, payload, date: DateTime.now().toUTC().toISO() }, null, 4) : null
        const headers = {
            ...(auth && { Authorization: await this.getAuthToken() }),
            ...(bodyString && { "Content-Type": "application/json" }),
            ...(signed && bodyString && { "Content-Signature": await this.signMessage(bodyString) })
        }
        return await fetch(`${this.apiUrl}${endpoint}${queryParams ? `?${new URLSearchParams(queryParams).toString()}` : ""}`, {
            method,
            headers,
            body: bodyString
        })
            .then(async res => {
                let bodyObject: Record<string, any> = {}
                if (res.ok) {
                    try { bodyObject = await res.json() }
                    catch { }
                }
                return {
                    status: res.status,
                    body: bodyObject
                }
            })
    }

    submitSignedAuthRequest = async (): Promise<TokenResponse> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.VERIFY_SIGNATURE, { method: "POST", signed: true })
        return { status, token: body.token }
    }

    getEmailChallenge = async (email: string): Promise<StatusResponse> => {
        const { status } = await this.fetchBase(ENDPOINTS.EMAIL_CHALLENGE, { method: "GET", queryParams: { email } })
        return { status }
    }

    submitEmailChallenge = async (challenge: string): Promise<TokenResponse> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.VERIFY_EMAIL, { method: "POST", queryParams: { challenge } })
        return { status, token: body.token }
    }

    getAdministrators = async (): Promise<DataResponse<Administrator[]>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.ADMINISTRATORS, { method: "GET", auth: true })
        return { status, data: body.data }
    }

    getAdministratorInfo = async (adminId: string | number): Promise<DataResponse<Administrator>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.ADMINISTRATOR(adminId), { method: "GET", auth: true })
        return { status, data: body.data }
    }

    getAssets = async (): Promise<DataResponse<Asset[]>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.ASSETS, { method: "GET", auth: true })
        return { status, data: body.data }
    }

    getAssetSettings = async (): Promise<DataResponse<AssetSettings[]>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.ASSET_SETTINGS, { method: "GET", auth: true })
        return { status, data: body.data }
    }

    getAssetPrices = async (): Promise<DataResponse<AssetPrice[]>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.PRICES, { method: "GET", auth: true })
        return { status, data: body.data }
    }

    getAssetBalances = async (): Promise<DataResponse<AssetBalance[]>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.BALANCES, { method: "GET", auth: true })
        return { status, data: body.data }
    }

    getAssetSources = async (): Promise<DataResponse<AssetSource[]>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.SOURCES, { method: "GET", auth: true })
        return { status, data: body.data }
    }

    getUnitHoldersRegister = async (): Promise<DataResponse<UnitHoldersRegisterEntry[]>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.UNIT_HOLDERS_REGISTER, { method: "GET", auth: true })
        return { status, data: body.data }

    }

    getAccounts = async (): Promise<DataResponse<Account[]>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.ACCOUNTS, { method: "GET", auth: true })
        return { status, data: body.data }

    }

    getClientsForAccount = async (accountId: string | number): Promise<DataResponse<Client[]>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.CLIENTS_FOR_ACCOUNT(accountId), { method: "GET", auth: true })
        return { status, data: body.data }

    }

    getClients = async (): Promise<DataResponse<Client>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.CLIENTS, { method: "GET", auth: true })
        return { status, data: body.data }

    }

    getAccountsForClient = async (clientId: string | number): Promise<DataResponse<Account[]>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.ACCOUNTS_FOR_CLIENT(clientId), { method: "GET", auth: true })
        return { status, data: body.data }

    }

    getHistoricalFundMetrics = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<FundMetricsEntry[]>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.HISTORICAL_FUND_METRICS, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        return { status, data: body.data }

    }

    getRecentFundMetrics = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<FundMetricsEntry[]>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.RECENT_FUND_METRICS, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        return { status, data: body.data }

    }

    getInvestorPortalAccessLog = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<InvestorPortalAccessLogEntry[]>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.INVESTOR_PORTAL_ACCESS_LOG, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        return { status, data: body.data }

    }

    getInvestorPortalOptions = async (): Promise<DataResponse<InvestorPortalOptions>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.INVESTOR_PORTAL_OPTIONS, { method: "GET", auth: true })
        return { status, data: body.data }

    }

    getModificationEventLog = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<ModificationLogEntry[]>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.MODIFICATION_EVENT_LOG, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        return { status, data: body.data }

    }

    getFeeCalculation = async (valuationDate: string | Date | DateTime, aum: string): Promise<DataResponse<FeeCalculation>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.CALCULATE_FEES, { method: "GET", queryParams: { valuationDate: toISO(valuationDate), aum }, auth: true })
        return { status, data: body.data }
    }

    updateAssetSettingsForAsset = async (assetName: string, assetSymbol: string, manualBalance: number, manualAUDPrice: number): Promise<StatusResponse> => {
        const { status } = await this.fetchBase(ENDPOINTS.SETTINGS_FOR_ASSET(assetName), {
            method: "PUT",
            payload: { assetName, assetSymbol, manualBalance, manualAUDPrice },
            signed: true
        })
        return { status }
    }

    createClient = async (email: string, firstName: string, lastName: string): Promise<DataResponse<Client>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.CLIENTS, {
            method: "POST",
            payload: { email, firstName, lastName },
            signed: true
        })
        return { status, data: body.data }
    }

    updateClient = async (clientId: string | number, email: string, firstName: string, lastName: string): Promise<StatusResponse> => {
        const { status } = await this.fetchBase(ENDPOINTS.CLIENT(clientId), {
            method: "PUT",
            payload: { email, firstName, lastName },
            signed: true
        })
        return { status }
    }

    createAccount = async (accountName: string, entityType: string, address: string, suburb: string, state: string, postcode: string, country: string): Promise<DataResponse<Account>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.ACCOUNTS, {
            method: "POST",
            payload: { accountName, entityType, address, suburb, state, postcode, country },
            signed: true
        })
        return { status, data: body.data }
    }

    updateAccount = async (accountId: string | number, accountName: string, entityType: string, address: string, suburb: string, state: string, postcode: string, country: string): Promise<StatusResponse> => {
        const { status } = await this.fetchBase(ENDPOINTS.ACCOUNT(accountId), {
            method: "PUT",
            payload: { accountName, entityType, address, suburb, state, postcode, country },
            signed: true
        })
        return { status }
    }

    updateClientsForAccount = async (accountId: string | number, clientIds: string[] | number[]): Promise<StatusResponse> => {
        const { status } = await this.fetchBase(ENDPOINTS.CLIENTS_FOR_ACCOUNT(accountId), {
            method: "PUT",
            payload: { clientIds },
            signed: true
        })
        return { status }
    }

    createUnitHoldersRegisterEntry = async (date: string | Date | DateTime, accountId: string | number, vintage: string | number, unitsAcquiredOrRedeemed: number, unitPrice: number ): Promise<DataResponse<UnitHoldersRegisterEntry>> => {
        const { status, body } = await this.fetchBase(ENDPOINTS.UNIT_HOLDERS_REGISTER, {
            method: "POST",
            payload: { date: toISO(date), accountId, vintage, unitsAcquiredOrRedeemed, unitPrice },
            signed: true
        })
        return { status, data: body.data }
    }

    updateInvestorPortalOptions = async (maintenanceMode: string | number, soapboxTitle: string, soapboxBody: string): Promise<StatusResponse> => {
        const { status } = await this.fetchBase(ENDPOINTS.INVESTOR_PORTAL_OPTIONS, {
            method: "PUT",
            payload: { maintenanceMode, soapboxTitle, soapboxBody },
            signed: true
        })
        return { status }
    }
}
