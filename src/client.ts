import jwt from "jsonwebtoken"
import { DateTime } from "luxon"
import { signMessageWithEthereumPrivateKey } from "./signing"
import { Account, Administrator, Asset, AssetBalance, AssetPrice, AssetSettings, AssetSource, AssetSnapshotsEntry, Client, FeeCalculation, FundMetricsEntry, InvestorPortalAccessLogEntry, InvestorPortalOptions, ModificationLogEntry, UnitHoldersRegisterEntry } from "@blockchain-assets-pty-ltd/data-types"

const ENDPOINTS = {
    VERIFY_SIGNATURE: "/v1/token/verify_signature",
    EMAIL_CHALLENGE: "/v1/token/email_challenge",
    VERIFY_EMAIL: "/v1/token/verify_email",
    REFRESH: "/v1/token/refresh",
    ADMINISTRATORS: "/v1/administrators",
    ADMINISTRATOR: (adminId: number) => `/v1/administrators/${adminId}`,
    ASSETS: "/v1/assets",
    ASSET_SETTINGS: "/v1/assets/settings",
    SETTINGS_FOR_ASSET: (assetName: string) => `/v1/assets/settings/${encodeURIComponent(assetName)}`,
    PRICES: "/v1/assets/prices",
    PRICE_FOR_ASSET: (assetName: string) => `/v1/assets/prices/${encodeURIComponent(assetName)}`,
    BALANCES: "/v1/assets/balances",
    BALANCE_FOR_ASSET: (assetName: string) => `/v1/assets/balances/${encodeURIComponent(assetName)}`,
    SOURCES: "/v1/assets/sources",
    ASSET_SNAPSHOTS: "/v1/assets/snapshots",
    UNIT_HOLDERS_REGISTER: "/v1/unit_holders_register",
    ACCOUNTS: "/v1/accounts",
    ACCOUNT: (accountId: number) => `/v1/accounts/${accountId}`,
    CLIENTS_FOR_ACCOUNT: (accountId: number) => `/v1/accounts/${accountId}/registered_clients`,
    CLIENTS: "/v1/clients",
    CLIENT: (clientId: number) => `/v1/clients/${clientId}`,
    ACCOUNTS_FOR_CLIENT: (clientId: number) => `/v1/clients/${clientId}/registered_accounts`,
    HISTORICAL_FUND_METRICS: "/v1/fund_metrics/historical",
    RECENT_FUND_METRICS: "/v1/fund_metrics/recent",
    INVESTOR_PORTAL_ACCESS_LOG: "/v1/investor_portal/access_log",
    INVESTOR_PORTAL_OPTIONS: "/v1/investor_portal/options",
    INVESTOR_PORTAL_FUND_OVERVIEW: "/v1/investor_portal/fund_overview",
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
    ok: boolean
    status: number
    body: Record<string, any>
}

type StatusResponse = {
    ok: boolean
    status: number
}

type TokenResponse = {
    ok: boolean
    status: number
    token?: string
}

type DataResponse<T> = {
    ok: boolean
    status: number
    data: T
}

type FundOverview = {
    lastUpdatedAt: DateTime
    unitPrice: number
    aum: number
    assets: Asset[]
    historicalFundMetrics: FundMetricsEntry[]
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

const fromISO = (date: string | null | undefined) => {
    if (date) return DateTime.fromISO(date)
}

export class BCA_API_Client {
    private apiUrl: string
    private authToken?: string
    private signingKey?: string
    private signingFunction?: Function
    private autoRequestNewAuthToken: boolean

    constructor(apiUrl: string, options: { authToken?: string, signingKey?: string, signingFunction?: Function }) {
        this.apiUrl = apiUrl
        this.authToken = options?.authToken
        this.signingKey = options?.signingKey
        this.signingFunction = options?.signingFunction

        this.autoRequestNewAuthToken = !!options?.signingKey
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
                    ok: res.ok,
                    status: res.status,
                    body: bodyObject
                }
            })
    }

    submitSignedAuthRequest = async (): Promise<TokenResponse> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.VERIFY_SIGNATURE, { method: "POST", signed: true })
        return { ok, status, token: body.token }
    }

    getEmailChallenge = async (email: string): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.EMAIL_CHALLENGE, { method: "GET", queryParams: { email } })
        return { ok, status }
    }

    submitEmailChallenge = async (challenge: string): Promise<TokenResponse> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.VERIFY_EMAIL, { method: "POST", queryParams: { challenge } })
        return { ok, status, token: body.token }
    }

    getRefreshToken = async (): Promise<TokenResponse> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.REFRESH, { method: "POST", auth: true })
        return { ok, status, token: body.token }
    }

    getAdministrators = async (): Promise<DataResponse<Administrator[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.ADMINISTRATORS, { method: "GET", auth: true })
        return { ok, status, data: body.data }
    }

    getAdministratorInfo = async (adminId: string | number): Promise<DataResponse<Administrator>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.ADMINISTRATOR(Number(adminId)), { method: "GET", auth: true })
        return { ok, status, data: body.data }
    }

    getAssets = async (): Promise<DataResponse<Asset[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.ASSETS, { method: "GET", auth: true })
        return { ok, status, data: body.data }
    }

    getAssetSettings = async (): Promise<DataResponse<AssetSettings[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.ASSET_SETTINGS, { method: "GET", auth: true })
        return { ok, status, data: body.data }
    }

    getAssetPrices = async (): Promise<DataResponse<AssetPrice[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.PRICES, { method: "GET", auth: true })
        const data: AssetPrice[] = body.data.map((item: any) => ({ ...item, lastUpdatedAt: fromISO(item.lastUpdatedAt) }))
        return { ok, status, data }
    }

    getAssetBalances = async (): Promise<DataResponse<AssetBalance[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.BALANCES, { method: "GET", auth: true })
        const data: AssetBalance[] = body.data.map((item: any) => ({ ...item, lastUpdatedAt: fromISO(item.lastUpdatedAt) }))
        return { ok, status, data }
    }

    getAssetSources = async (): Promise<DataResponse<AssetSource[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.SOURCES, { method: "GET", auth: true })
        return { ok, status, data: body.data }
    }

    getAssetSnapshots = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<AssetSnapshotsEntry[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.ASSET_SNAPSHOTS, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        const data: AssetSnapshotsEntry[] = body.data.map((item: any) => ({ ...item, date: fromISO(item.date) }))
        return { ok, status, data }
    }

    getUnitHoldersRegister = async (): Promise<DataResponse<UnitHoldersRegisterEntry[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.UNIT_HOLDERS_REGISTER, { method: "GET", auth: true })
        const data: UnitHoldersRegisterEntry[] = body.data.map((item: any) => ({ ...item, date: fromISO(item.date) }))
        return { ok, status, data }
    }

    getAccounts = async (): Promise<DataResponse<Account[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.ACCOUNTS, { method: "GET", auth: true })
        return { ok, status, data: body.data }
    }

    getClientsForAccount = async (accountId: string | number): Promise<DataResponse<Client[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.CLIENTS_FOR_ACCOUNT(Number(accountId)), { method: "GET", auth: true })
        const data: Client[] = body.data.map((item: any) => ({ ...item, lastAccessedAt: fromISO(item.lastAccessedAt) }))
        return { ok, status, data }
    }

    getClients = async (): Promise<DataResponse<Client[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.CLIENTS, { method: "GET", auth: true })
        const data: Client[] = body.data.map((item: any) => ({ ...item, lastAccessedAt: fromISO(item.lastAccessedAt) }))
        return { ok, status, data }
    }

    getClientInfo = async (clientId: number): Promise<DataResponse<Client>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.CLIENT(clientId), { method: "GET", auth: true })
        const data: Client = { ...body.data, lastAccessedAt: fromISO(body.data.lastAccessedAt) }
        return { ok, status, data }
    }

    getAccountsForClient = async (clientId: string | number): Promise<DataResponse<Account[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.ACCOUNTS_FOR_CLIENT(Number(clientId)), { method: "GET", auth: true })
        return { ok, status, data: body.data }
    }

    getHistoricalFundMetrics = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<FundMetricsEntry[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.HISTORICAL_FUND_METRICS, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        const data: FundMetricsEntry[] = body.data.map((item: any) => ({ ...item, date: fromISO(item.date) }))
        return { ok, status, data }
    }

    getRecentFundMetrics = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<FundMetricsEntry[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.RECENT_FUND_METRICS, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        const data: FundMetricsEntry[] = body.data.map((item: any) => ({ ...item, date: fromISO(item.date) }))
        return { ok, status, data }
    }

    getInvestorPortalAccessLog = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<InvestorPortalAccessLogEntry[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.INVESTOR_PORTAL_ACCESS_LOG, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        const data: InvestorPortalAccessLogEntry[] = body.data.map((item: any) => ({ ...item, date: fromISO(item.date) }))
        return { ok, status, data }
    }

    getInvestorPortalOptions = async (): Promise<DataResponse<InvestorPortalOptions>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.INVESTOR_PORTAL_OPTIONS, { method: "GET", auth: true })
        return { ok, status, data: body.data }
    }

    getInvestorPortalFundOverview = async (): Promise<DataResponse<FundOverview>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.INVESTOR_PORTAL_FUND_OVERVIEW, { method: "GET", auth: true })
        const data: FundOverview = {
            ...body.data,
            lastUpdatedAt: fromISO(body.data.lastUpdatedAt),
            historicalFundMetrics: body.data.historicalFundMetrics.map((item: any) => ({ ...item, date: fromISO(item.date) }))
        }
        return { ok, status, data }
    }

    getModificationEventLog = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<ModificationLogEntry[]>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.MODIFICATION_EVENT_LOG, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        const data: ModificationLogEntry[] = body.data.map((item: any) => ({ ...item, date: fromISO(item.date) }))
        return { ok, status, data }
    }

    getFeeCalculation = async (valuationDate: string | Date | DateTime, aum: number): Promise<DataResponse<FeeCalculation>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.CALCULATE_FEES, { method: "GET", queryParams: { valuationDate: toISO(valuationDate), aum }, auth: true })
        const data: FeeCalculation = {
            ...body.data,
            valuationDate: fromISO(body.data.valuationDate),
            vintages: body.data.vintages.map((v: any) => ({
                ...v,
                creationDate: fromISO(v.creationDate),
                latestFcEntry: {
                    ...(v.latestFcEntry && { ...v.latestFcEntry, date: fromISO(v.latestFcEntry.date) })
                },
                uhrEntries: v.uhrEntries.map((uhr: any) => ({
                    ...uhr,
                    date: fromISO(uhr.date)
                }))
            }))
        }
        return { ok, status, data }
    }

    updateAssetSettingsForAsset = async (assetName: string, assetSymbol: string, manualBalance: number, manualPrice: number): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.SETTINGS_FOR_ASSET(assetName), {
            method: "PUT",
            payload: { assetName, assetSymbol, manualBalance, manualPrice },
            signed: true
        })
        return { ok, status }
    }

    createClient = async (email: string, firstName: string, lastName: string): Promise<DataResponse<Client>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.CLIENTS, {
            method: "POST",
            payload: { email, firstName, lastName },
            signed: true
        })
        const data: Client = { ...body.data, lastAccessedAt: fromISO(body.data.lastAccessedAt) }
        return { ok, status, data }
    }

    updateClient = async (clientId: string | number, email: string, firstName: string, lastName: string): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.CLIENT(Number(clientId)), {
            method: "PUT",
            payload: { email, firstName, lastName },
            signed: true
        })
        return { ok, status }
    }

    createAccount = async (accountName: string, entityType: string, address: string, suburb: string, state: string, postcode: string, country: string): Promise<DataResponse<Account>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.ACCOUNTS, {
            method: "POST",
            payload: { accountName, entityType, address, suburb, state, postcode, country },
            signed: true
        })
        return { ok, status, data: body.data }
    }

    updateAccount = async (accountId: string | number, accountName: string, entityType: string, address: string, suburb: string, state: string, postcode: string, country: string): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.ACCOUNT(Number(accountId)), {
            method: "PUT",
            payload: { accountName, entityType, address, suburb, state, postcode, country },
            signed: true
        })
        return { ok, status }
    }

    updateClientsForAccount = async (accountId: string | number, clientIds: string[] | number[]): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.CLIENTS_FOR_ACCOUNT(Number(accountId)), {
            method: "PUT",
            payload: { clientIds },
            signed: true
        })
        return { ok, status }
    }

    createUnitHoldersRegisterEntry = async (date: string | Date | DateTime, accountId: string | number, vintage: string | number, unitsAcquiredOrRedeemed: number, unitPrice: number): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.UNIT_HOLDERS_REGISTER, {
            method: "POST",
            payload: { date: toISO(date), accountId, vintage, unitsAcquiredOrRedeemed, unitPrice },
            signed: true
        })
        return { ok, status }
    }

    updateInvestorPortalOptions = async (maintenanceMode: string | number, soapboxTitle: string, soapboxBody: string): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.INVESTOR_PORTAL_OPTIONS, {
            method: "PUT",
            payload: { maintenanceMode, soapboxTitle, soapboxBody },
            signed: true
        })
        return { ok, status }
    }

    createAssetPrice = async (assetName: string, price: number): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.PRICE_FOR_ASSET(assetName), {
            method: "PUT",
            payload: { price },
            signed: true
        })
        return { ok, status }
    }

    deleteAssetPrice = async (assetName: string): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.PRICE_FOR_ASSET(assetName), {
            method: "DELETE",
            signed: true
        })
        return { ok, status }
    }

    createAssetBalance = async (assetName: string, sourceId: number, balance: number): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.BALANCE_FOR_ASSET(assetName), {
            method: "PUT",
            payload: { sourceId, balance },
            signed: true
        })
        return { ok, status }
    }

    deleteAssetBalance = async (assetName: string, sourceId: number): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.BALANCE_FOR_ASSET(assetName), {
            method: "DELETE",
            payload: { sourceId },
            signed: true
        })
        return { ok, status }
    }

    createHistoricalFundMetricsEntry = async (date: string | Date | DateTime, unitPrice: number, aum: number): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.HISTORICAL_FUND_METRICS, {
            method: "PUT",
            payload: { date: toISO(date), unitPrice, aum },
            signed: true
        })
        return { ok, status }
    }

    createRecentFundMetricsEntry = async (date: string | Date | DateTime, unitPrice: number, aum: number): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.RECENT_FUND_METRICS, {
            method: "PUT",
            payload: { date: toISO(date), unitPrice, aum },
            signed: true
        })
        return { ok, status }
    }

    takeSnapshotOfAssets = async (): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.ASSET_SNAPSHOTS, {
            method: "POST",
            payload: {},
            signed: true
        })
        return { ok, status }
    }
}
