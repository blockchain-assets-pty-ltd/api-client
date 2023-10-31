import type { Account, Administrator, Asset, AssetBalance, AssetPrice, AssetSettings, AssetSource, AssetSnapshotsEntry, Bot, Client, FeeCalculation, FundMetricsEntry, InvestorPortalAccessLogEntry, InvestorPortalOptions, ModificationLogEntry, UnitHoldersRegisterEntry, FeeCapitalisationsEntry, AttributionCalculation, AttributedDistributionsEntry, TaxDistribution, Job, Liability, TaxFileNumber } from "@blockchain-assets-pty-ltd/shared"
import jwt from "jsonwebtoken"
import type { Big } from "big.js"
import { DateTime } from "luxon"
import { signMessageWithEthereumPrivateKey } from "./signing"
import Deserialise from "./deserialisation"

type FetchOptions = {
    method: string
    auth?: boolean
    queryParams?: Record<string, any>
    signed: true
    payload?: Record<string, any>
} | {
    method: string
    auth?: boolean
    queryParams?: Record<string, any>
    signed?: false
    body?: Record<string, any>
}

type APIResponse = {
    ok: boolean
    status: number
    body: Record<string, any>
}

export type StatusResponse = {
    ok: boolean
    status: number
}

export type TokenResponse = {
    ok: true
    status: number
    token: string
} | {
    ok: false
    status: number
}

export type DataResponse<T> = {
    ok: true
    status: number
    data: T
} | {
    ok: false
    status: number
}

export type FundOverview = {
    lastUpdatedAt: DateTime
    unitPrice: Big
    aum: Big
    assets: Asset[]
    historicalFundMetrics: FundMetricsEntry[]
}

const ENDPOINTS = {
    VERIFY_SIGNATURE: "/v1/token/verify_signature",
    EMAIL_CHALLENGE: "/v1/token/email_challenge",
    VERIFY_EMAIL: "/v1/token/verify_email",
    REFRESH: "/v1/token/refresh",
    GENERATE_INVESTOR_PORTAL_LINK: "/v1/token/generate_investor_portal_link",
    ADMINISTRATORS: "/v1/administrators",
    ADMINISTRATOR: (adminId: number) => `/v1/administrators/${adminId}`,
    BOTS: "/v1/bots",
    BOT: (botId: number) => `/v1/bots/${botId}`,
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
    ACQUISITION: "/v1/unit_holders_register/acquisition",
    REDEMPTION: "/v1/unit_holders_register/redemption",
    REDEMPTION_PREVIEW: "/v1/unit_holders_register/redemption/preview",
    CALCULATE_FEES: "/v1/fees/calculate",
    DISTRIBUTIONS: "/v1/tax/distributions",
    ATTRIBUTE_DISTRIBUTIONS: "/v1/tax/distributions/attribute",
    ATTRIBUTE_DISTRIBUTIONS_PREVIEW: "/v1/tax/distributions/attribute/preview",
    CAPITALISATIONS: "/v1/fees/capitalisations",
    ACCOUNTS: "/v1/accounts",
    ACCOUNT: (accountId: number) => `/v1/accounts/${accountId}`,
    REGISTERED_CLIENTS: (accountId: number) => `/v1/accounts/${accountId}/registered_clients`,
    REGISTERED_TFNS: (accountId: number) => `/v1/accounts/${accountId}/registered_tfns`,
    CLIENTS: "/v1/clients",
    CLIENT: (clientId: number) => `/v1/clients/${clientId}`,
    REGISTERED_ACCOUNTS: (clientId: number) => `/v1/clients/${clientId}/registered_accounts`,
    HISTORICAL_FUND_METRICS: "/v1/fund_metrics/historical",
    RECENT_FUND_METRICS: "/v1/fund_metrics/recent",
    INVESTOR_PORTAL_ACCESS_LOG: "/v1/investor_portal/access_log",
    INVESTOR_PORTAL_OPTIONS: "/v1/investor_portal/options",
    INVESTOR_PORTAL_FUND_OVERVIEW: "/v1/investor_portal/fund_overview",
    MODIFICATION_EVENT_LOG: "/v1/audit/modification_event_log",
    AVAILABLE_STATEMENTS: (accountId: number) => `/v1/documents/available_statements/${accountId}`,
    GENERATE_ACCOUNT_STATEMENT: (accountId: number) => `/v1/documents/generate/account_statement/${accountId}`,
    GENERATE_TAX_STATEMENT: (accountId: number) => `/v1/documents/generate/tax_statement/${accountId}`,
    JOBS: "/v1/jobs",
    JOB: (jobId: string) => `/v1/jobs/${jobId}`,
    JOB_TYPES: "/v1/job_types",
    LIABILITIES: "/v1/liabilities",
    LIABILITY: (liabilityId: number) => `/v1/liabilities/${liabilityId}`,
    CLEAR_LIABILITY: (liabilityId: number) => `/v1/liabilities/${liabilityId}/clear`
}

const toISO = (date: string | Date | DateTime): string => {
    if (date instanceof Date) {
        return date.toISOString()
    }
    else if (date instanceof DateTime) {
        if (date.isValid)
            return date.toUTC().toISO()!
        else
            throw new Error("The provided DateTime was invalid.")
    }
    else {
        const dateTime = DateTime.fromJSDate(new Date(date))
        if (dateTime.isValid)
            return dateTime.toUTC().toISO()!
        else
            throw new Error(`The provided value could not be parsed to a valid date: '${date}'`)
    }
}

export class BCA_API_Client {
    private apiUrl: string
    private authToken?: string
    private signingKey?: string
    private signingFunction?: Function
    private extraFetchArgs?: Record<string, any>
    private autoRequestNewAuthToken: boolean

    constructor(apiUrl: string, options: { authToken?: string, signingKey?: string, signingFunction?: Function, extraFetchArgs?: Record<string, any> }) {
        this.apiUrl = apiUrl
        this.authToken = options?.authToken
        this.signingKey = options?.signingKey
        this.signingFunction = options?.signingFunction
        this.extraFetchArgs = options?.extraFetchArgs

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
            const response = await this.submitSignedAuthRequest()
            if (!response.ok) {
                throw new Error("Failed to obtain new auth token.")
            }
            else {
                this.authToken = response.token
                return this.authToken
            }
        }
    }

    private signMessage = async (message: string): Promise<string> => {
        if (this.signingFunction) {
            return await this.signingFunction(message)
        }
        else if (this.signingKey) {
            return signMessageWithEthereumPrivateKey(message, this.signingKey)
        }
        else {
            throw new Error("Cannot sign message - no signing function or signing key supplied.")
        }
    }

    private fetchBase = async (endpoint: string, fetchOptions: FetchOptions): Promise<APIResponse> => {
        const { method, auth, queryParams, signed } = fetchOptions
        const bodyString = JSON.stringify(signed ? { endpoint: `${method} ${endpoint}`, payload: fetchOptions.payload, date: DateTime.now().toUTC().toISO() } : fetchOptions.body)
        const headers = {
            ...(auth && { Authorization: await this.getAuthToken() }),
            ...(bodyString && { "Content-Type": "application/json" }),
            ...(signed && bodyString && { "Content-Signature": await this.signMessage(bodyString) })
        }
        return await fetch(`${this.apiUrl}${endpoint}${queryParams ? `?${new URLSearchParams(queryParams).toString()}` : ""}`, {
            method,
            headers,
            body: bodyString,
            ...this.extraFetchArgs
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

    private createDataResponse = <T>(apiResponse: APIResponse, deserialiser: (data: any) => T): DataResponse<T> => {
        if (apiResponse.ok)
            return { ok: apiResponse.ok, status: apiResponse.status, data: deserialiser(apiResponse.body.data) }
        else
            return { ok: apiResponse.ok, status: apiResponse.status }
    }

    submitSignedAuthRequest = async (): Promise<TokenResponse> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.VERIFY_SIGNATURE, { method: "POST", signed: true })
        return { ok, status, token: !ok ? undefined : body.token }
    }

    getEmailChallenge = async (email: string): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.EMAIL_CHALLENGE, { method: "GET", queryParams: { email } })
        return { ok, status }
    }

    submitEmailChallenge = async (challenge: string): Promise<TokenResponse> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.VERIFY_EMAIL, { method: "POST", queryParams: { challenge } })
        return { ok, status, token: !ok ? undefined : body.token }
    }

    getRefreshToken = async (): Promise<TokenResponse> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.REFRESH, { method: "POST", auth: true })
        return { ok, status, token: !ok ? undefined : body.token }
    }

    getAdministrators = async (): Promise<DataResponse<Administrator[]>> => {
        const response = await this.fetchBase(ENDPOINTS.ADMINISTRATORS, { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.Administrator))
    }

    getAdministratorInfo = async (adminId: number): Promise<DataResponse<Administrator>> => {
        const response = await this.fetchBase(ENDPOINTS.ADMINISTRATOR(adminId), { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Administrator(data))
    }

    getBots = async (): Promise<DataResponse<Bot[]>> => {
        const response = await this.fetchBase(ENDPOINTS.BOTS, { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.Bot))
    }

    getBotInfo = async (botId: number): Promise<DataResponse<Bot>> => {
        const response = await this.fetchBase(ENDPOINTS.BOT(botId), { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Bot(data))
    }

    getAssets = async (): Promise<DataResponse<Asset[]>> => {
        const response = await this.fetchBase(ENDPOINTS.ASSETS, { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.Asset))
    }

    getAssetSettings = async (): Promise<DataResponse<AssetSettings[]>> => {
        const response = await this.fetchBase(ENDPOINTS.ASSET_SETTINGS, { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.AssetSettings))
    }

    getAssetPrices = async (): Promise<DataResponse<AssetPrice[]>> => {
        const response = await this.fetchBase(ENDPOINTS.PRICES, { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.AssetPrice))
    }

    getAssetBalances = async (): Promise<DataResponse<AssetBalance[]>> => {
        const response = await this.fetchBase(ENDPOINTS.BALANCES, { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.AssetBalance))
    }

    getAssetSources = async (): Promise<DataResponse<AssetSource[]>> => {
        const response = await this.fetchBase(ENDPOINTS.SOURCES, { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.AssetSource))
    }

    getAssetSnapshots = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<AssetSnapshotsEntry[]>> => {
        const response = await this.fetchBase(ENDPOINTS.ASSET_SNAPSHOTS, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.AssetSnapshotsEntry))
    }

    getUnitHoldersRegister = async (): Promise<DataResponse<UnitHoldersRegisterEntry[]>> => {
        const response = await this.fetchBase(ENDPOINTS.UNIT_HOLDERS_REGISTER, { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.UnitHoldersRegisterEntry))
    }

    getAccounts = async (): Promise<DataResponse<Account[]>> => {
        const response = await this.fetchBase(ENDPOINTS.ACCOUNTS, { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.Account))
    }

    getClientsForAccount = async (accountId: number): Promise<DataResponse<Client[]>> => {
        const response = await this.fetchBase(ENDPOINTS.REGISTERED_CLIENTS(accountId), { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.Client))
    }

    getClients = async (): Promise<DataResponse<Client[]>> => {
        const response = await this.fetchBase(ENDPOINTS.CLIENTS, { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.Client))
    }

    getClientInfo = async (clientId: number): Promise<DataResponse<Client>> => {
        const response = await this.fetchBase(ENDPOINTS.CLIENT(clientId), { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Client(data))
    }

    getAccountsForClient = async (clientId: number): Promise<DataResponse<Account[]>> => {
        const response = await this.fetchBase(ENDPOINTS.REGISTERED_ACCOUNTS(clientId), { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.Account))
    }

    getTaxFileNumbersForAccount = async (accountId: number): Promise<DataResponse<TaxFileNumber[]>> => {
        const response = await this.fetchBase(ENDPOINTS.REGISTERED_TFNS(accountId), { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.TaxFileNumber))
    }

    getHistoricalFundMetrics = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<FundMetricsEntry[]>> => {
        const response = await this.fetchBase(ENDPOINTS.HISTORICAL_FUND_METRICS, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.FundMetricsEntry))
    }

    getRecentFundMetrics = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<FundMetricsEntry[]>> => {
        const response = await this.fetchBase(ENDPOINTS.RECENT_FUND_METRICS, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.FundMetricsEntry))
    }

    getInvestorPortalAccessLog = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<InvestorPortalAccessLogEntry[]>> => {
        const response = await this.fetchBase(ENDPOINTS.INVESTOR_PORTAL_ACCESS_LOG, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.InvestorPortalAccessLogEntry))
    }

    getInvestorPortalOptions = async (): Promise<DataResponse<InvestorPortalOptions>> => {
        const response = await this.fetchBase(ENDPOINTS.INVESTOR_PORTAL_OPTIONS, { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.InvestorPortalOptions(data))
    }

    getInvestorPortalFundOverview = async (): Promise<DataResponse<FundOverview>> => {
        const response = await this.fetchBase(ENDPOINTS.INVESTOR_PORTAL_FUND_OVERVIEW, { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.FundOverview(data))
    }

    getModificationEventLog = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<ModificationLogEntry[]>> => {
        const response = await this.fetchBase(ENDPOINTS.MODIFICATION_EVENT_LOG, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.ModificationLogEntry))
    }

    getFeeCalculation = async (valuationDate: string | Date | DateTime, aum: Big): Promise<DataResponse<FeeCalculation>> => {
        const response = await this.fetchBase(ENDPOINTS.CALCULATE_FEES, { method: "GET", queryParams: { valuationDate: toISO(valuationDate), aum }, auth: true })
        return this.createDataResponse(response, (data) => Deserialise.FeeCalculation(data))
    }

    getFeeCapitalisationsEntries = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<FeeCapitalisationsEntry[]>> => {
        const response = await this.fetchBase(ENDPOINTS.CAPITALISATIONS, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.FeeCapitalisationsEntry))
    }

    getAttributedDistributionsEntries = async (startDate: string | Date | DateTime, endDate: string | Date | DateTime): Promise<DataResponse<AttributedDistributionsEntry[]>> => {
        const response = await this.fetchBase(ENDPOINTS.DISTRIBUTIONS, { method: "GET", queryParams: { startDate: toISO(startDate), endDate: toISO(endDate) }, auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.AttributedDistributionsEntry))
    }

    getJobs = async (): Promise<DataResponse<Job[]>> => {
        const response = await this.fetchBase(ENDPOINTS.JOBS, { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.Job))
    }

    getJobInfo = async (jobId: string): Promise<DataResponse<Job>> => {
        const response = await this.fetchBase(ENDPOINTS.JOB(jobId), { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Job(data))
    }

    getJobTypes = async (): Promise<DataResponse<{ type: string, parameterNames: string[] }[]>> => {
        const response = await this.fetchBase(ENDPOINTS.JOB_TYPES, { method: "GET", auth: true })
        return this.createDataResponse(response, (data) => data)
    }

    getLiabilities = async (outstandingOnly: boolean): Promise<DataResponse<Liability[]>> => {
        const response = await this.fetchBase(ENDPOINTS.LIABILITIES, { method: "GET", queryParams: { outstandingOnly }, auth: true })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.Liability))
    }

    updateAssetSettingsForAsset = async (assetName: string, assetSymbol: string | null, manualBalance: Big | null, manualPrice: Big | null): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.SETTINGS_FOR_ASSET(assetName), {
            method: "PUT",
            payload: { assetName, assetSymbol, manualBalance, manualPrice },
            signed: true
        })
        return { ok, status }
    }

    createClient = async (email: string, firstName: string, lastName: string): Promise<DataResponse<Client>> => {
        const response = await this.fetchBase(ENDPOINTS.CLIENTS, {
            method: "POST",
            payload: { email, firstName, lastName },
            signed: true
        })
        return this.createDataResponse(response, (data) => Deserialise.Client(data))
    }

    updateClient = async (clientId: number, email: string, firstName: string, lastName: string): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.CLIENT(Number(clientId)), {
            method: "PUT",
            payload: { email, firstName, lastName },
            signed: true
        })
        return { ok, status }
    }

    createAccount = async (accountName: string, entityType: Account["entityType"], addressLine1: string, addressLine2: string, suburb: string, state: string, postcode: string, country: string, distributionReinvestmentPercentage: Big, accountTFN: string | null, partnershipTFNs: { taxFileNumber: string, clientId: number }[] | null): Promise<DataResponse<Account>> => {
        const response = await this.fetchBase(ENDPOINTS.ACCOUNTS, {
            method: "POST",
            payload: { accountName, entityType, addressLine1, addressLine2, suburb, state, postcode, country, distributionReinvestmentPercentage, accountTFN, partnershipTFNs },
            signed: true
        })
        return this.createDataResponse(response, (data) => Deserialise.Account(data))
    }

    updateAccount = async (accountId: number, accountName: string, entityType: Account["entityType"], addressLine1: string, addressLine2: string, suburb: string, state: string, postcode: string, country: string, distributionReinvestmentPercentage: Big, accountTFN: string | null, partnershipTFNs: { taxFileNumber: string, clientId: number }[] | null): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.ACCOUNT(accountId), {
            method: "PUT",
            payload: { accountName, entityType, addressLine1, addressLine2, suburb, state, postcode, country, distributionReinvestmentPercentage, accountTFN, partnershipTFNs },
            signed: true
        })
        return { ok, status }
    }

    updateClientsForAccount = async (accountId: number, clientIds: number[]): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.REGISTERED_CLIENTS(accountId), {
            method: "PUT",
            payload: { clientIds },
            signed: true
        })
        return { ok, status }
    }

    updateInvestorPortalOptions = async (maintenanceMode: boolean, soapboxTitle: string, soapboxBody: string): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.INVESTOR_PORTAL_OPTIONS, {
            method: "PUT",
            payload: { maintenanceMode, soapboxTitle, soapboxBody },
            signed: true
        })
        return { ok, status }
    }

    createAssetPrice = async (assetName: string, price: Big): Promise<StatusResponse> => {
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

    createAssetBalance = async (assetName: string, sourceId: number, balance: Big): Promise<StatusResponse> => {
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

    recordHistoricalFundMetricsEntry = async (): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.HISTORICAL_FUND_METRICS, {
            method: "POST",
            signed: true
        })
        return { ok, status }
    }

    recordRecentFundMetricsEntry = async (): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.RECENT_FUND_METRICS, {
            method: "POST",
            signed: true
        })
        return { ok, status }
    }

    performUnitAcquisition = async (acquisitionDate: string | Date | DateTime, accountId: number, fundsInvested: Big): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.ACQUISITION, {
            method: "POST",
            payload: { acquisitionDate: toISO(acquisitionDate), accountId, fundsInvested },
            signed: true
        })
        return { ok, status }
    }

    performUnitRedemption = async (redemptionDate: string | Date | DateTime, accountId: number, redeemedUnits: Big): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.REDEMPTION, {
            method: "POST",
            payload: { redemptionDate: toISO(redemptionDate), accountId, redeemedUnits },
            signed: true
        })
        return { ok, status }
    }

    getUnitRedemptionPreview = async (redemptionDate: string | Date | DateTime, accountId: number, redeemedUnits: Big): Promise<DataResponse<UnitHoldersRegisterEntry[]>> => {
        const response = await this.fetchBase(ENDPOINTS.REDEMPTION_PREVIEW, {
            method: "GET",
            queryParams: { redemptionDate: toISO(redemptionDate), accountId, redeemedUnits },
            auth: true
        })
        return this.createDataResponse(response, (data) => Deserialise.Array(data, Deserialise.UnitHoldersRegisterEntry))
    }

    takeSnapshotOfAssets = async (): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.ASSET_SNAPSHOTS, {
            method: "POST",
            payload: {},
            signed: true
        })
        return { ok, status }
    }

    capitaliseFees = async (capitalisationDate: DateTime): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.CAPITALISATIONS, {
            method: "POST",
            payload: { capitalisationDate },
            signed: true
        })
        return { ok, status }
    }

    getAvailableStatements = async (accountId: number): Promise<DataResponse<{ [statementType: string]: number[] }>> => {
        const { ok, status, body } = await this.fetchBase(ENDPOINTS.AVAILABLE_STATEMENTS(accountId), { method: "GET", auth: true })
        return { ok, status, data: !ok ? undefined : body.data }
    }

    requestStatement = async (statementType: "Account Statement" | "Tax Statement", financialYear: number, accountId: number): Promise<StatusResponse> => {
        let endpoint
        switch (statementType) {
            case "Account Statement":
                endpoint = ENDPOINTS.GENERATE_ACCOUNT_STATEMENT
                break
            case "Tax Statement":
                endpoint = ENDPOINTS.GENERATE_TAX_STATEMENT
                break
            default:
                throw new Error("Unknown statement type.")
        }
        const { ok, status } = await this.fetchBase(endpoint(accountId), {
            method: "POST",
            queryParams: { financialYear },
            auth: true
        })
        return { ok, status }
    }

    performDistributionAttribution = async (
        financialYear: number,
        taxPool: TaxDistribution,
        cashPool: Big,
        streamedTax: ({ accountId: number } & TaxDistribution)[],
    ): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.ATTRIBUTE_DISTRIBUTIONS, {
            method: "POST",
            payload: {
                financialYear,
                taxPool,
                cashPool,
                streamedTax
            },
            signed: true
        })
        return { ok, status }
    }

    getDistributionAttributionPreview = async (
        financialYear: number,
        taxPool: TaxDistribution,
        cashPool: Big,
        streamedTax: ({ accountId: number } & TaxDistribution)[],
    ): Promise<DataResponse<AttributionCalculation>> => {
        const response = await this.fetchBase(ENDPOINTS.ATTRIBUTE_DISTRIBUTIONS_PREVIEW, {
            method: "POST",
            body: {
                financialYear,
                taxPool,
                cashPool,
                streamedTax
            },
            auth: true
        })
        return this.createDataResponse(response, (data) => Deserialise.AttributionCalculation(data))
    }

    startJob = async (jobType: string, parameters: Record<string, any>): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.JOBS, {
            method: "POST",
            payload: {
                jobType,
                parameters
            },
            signed: true
        })
        return { ok, status }
    }

    stopJob = async (jobId: string): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.JOB(jobId), {
            method: "POST",
            signed: true
        })
        return { ok, status }
    }

    deleteJob = async (jobId: string): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.JOB(jobId), {
            method: "DELETE",
            auth: true
        })
        return { ok, status }
    }

    clearLiability = async (liabilityId: number): Promise<StatusResponse> => {
        const { ok, status } = await this.fetchBase(ENDPOINTS.CLEAR_LIABILITY(liabilityId), {
            method: "POST",
            signed: true
        })
        return { ok, status }
    }

    generateInvestorPortalLink = async (clientId: number, expiresIn: string): Promise<DataResponse<string>> => {
        const response = await this.fetchBase(ENDPOINTS.GENERATE_INVESTOR_PORTAL_LINK, {
            method: "POST",
            payload: {
                clientId,
                expiresIn
            },
            signed: true
        })
        return this.createDataResponse(response, (data) => data)
    }
}
