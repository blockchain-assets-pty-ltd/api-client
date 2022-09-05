import jwt from "jsonwebtoken"
import { signMessageWithEthereumPrivateKey } from "./signing"

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
    UNIT_PRICE: "/v1/fund_metrics/unit_price",
    AUM: "/v1/fund_metrics/aum",
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
            if (decoded && decoded.exp && decoded.exp * 1000 > Date.now()) {
                return this.authToken
            }
            else {
                this.authToken = undefined
            }
        }

        // If possible, request a new token.
        if (this.autoRequestNewAuthToken) {
            const token = (await this.submitSignedAuthRequest()).body.token
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
        const bodyString = signed ? JSON.stringify({ endpoint: `${method} ${endpoint}`, payload, date: new Date() }, null, 4) : null
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
            .then(async res => ({
                status: res.status,
                body: res.ok ? await res.json() : {}
            }))
    }

    private submitSignedAuthRequest = async (): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.VERIFY_SIGNATURE, {
            method: "POST",
            signed: true
        })
    }

    getEmailChallenge = async (email: string): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.EMAIL_CHALLENGE, { method: "GET", queryParams: { email } })
    }

    submitEmailChallenge = async (challenge: string): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.VERIFY_EMAIL, { method: "POST", queryParams: { challenge } })
    }

    getAdministrators = async (): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.ADMINISTRATORS, { method: "GET", auth: true })
    }

    getAdministratorInfo = async (adminId: string | number): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.ADMINISTRATOR(adminId), { method: "GET", auth: true })
    }

    getAssets = async (): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.ASSETS, { method: "GET", auth: true })
    }

    getAssetSettings = async (): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.ASSET_SETTINGS, { method: "GET", auth: true })
    }

    getAssetPrices = async (): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.PRICES, { method: "GET", auth: true })
    }

    getAssetBalances = async (): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.BALANCES, { method: "GET", auth: true })
    }

    getAssetSources = async (): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.SOURCES, { method: "GET", auth: true })
    }

    getUnitHoldersRegister = async (): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.UNIT_HOLDERS_REGISTER, { method: "GET", auth: true })
    }

    getAccounts = async (): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.ACCOUNTS, { method: "GET", auth: true })
    }

    getClientsForAccount = async (accountId: string | number): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.CLIENTS_FOR_ACCOUNT(accountId), { method: "GET", auth: true })
    }

    getClients = async (): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.CLIENTS, { method: "GET", auth: true })
    }

    getAccountsForClient = async (clientId: string | number): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.ACCOUNTS_FOR_CLIENT(clientId), { method: "GET", auth: true })
    }

    getUnitPriceHistory = async (sampleMode: string, startDate: string, endDate: string): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.UNIT_PRICE, { method: "GET", queryParams: { sampleMode, startDate, endDate }, auth: true })
    }

    getAUMHistory = async (sampleMode: string, startDate: string, endDate: string): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.AUM, { method: "GET", queryParams: { sampleMode, startDate, endDate }, auth: true })
    }

    getInvestorPortalAccessLog = async (startDate: string, endDate: string): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.INVESTOR_PORTAL_ACCESS_LOG, { method: "GET", queryParams: { startDate, endDate }, auth: true })
    }

    getInvestorPortalOptions = async (): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.INVESTOR_PORTAL_OPTIONS, { method: "GET", auth: true })
    }

    getModificationEventLog = async (startDate: string, endDate: string): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.MODIFICATION_EVENT_LOG, { method: "GET", queryParams: { startDate, endDate }, auth: true })
    }

    getFeeCalculation = async (valuationDate: Date, aum: string): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.CALCULATE_FEES, { method: "GET", queryParams: { valuationDate, aum }, auth: true })
    }

    updateAssetSettingsForAsset = async (assetName: string, assetSymbol: string, manualBalance: number, manualAUDPrice: number): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.SETTINGS_FOR_ASSET(assetName), {
            method: "PUT",
            payload: { assetName, assetSymbol, manualBalance, manualAUDPrice },
            signed: true
        })
    }

    createClient = async (email: string, firstName: string, lastName: string): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.CLIENTS, {
            method: "POST",
            payload: { email, firstName, lastName },
            signed: true
        })
    }

    updateClient = async (clientId: string | number, email: string, firstName: string, lastName: string): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.CLIENT(clientId), {
            method: "PUT",
            payload: { email, firstName, lastName },
            signed: true
        })
    }

    createAccount = async (accountName: string, entityType: string, address: string, suburb: string, state: string, postcode: string, country: string): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.ACCOUNTS, {
            method: "POST",
            payload: { accountName, entityType, address, suburb, state, postcode, country },
            signed: true
        })
    }

    updateAccount = async (accountId: string | number, accountName: string, entityType: string, address: string, suburb: string, state: string, postcode: string, country: string): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.ACCOUNT(accountId), {
            method: "PUT",
            payload: { accountName, entityType, address, suburb, state, postcode, country },
            signed: true
        })
    }

    updateClientsForAccount = async (accountId: string | number, clientIds: string[] | number[]): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.CLIENTS_FOR_ACCOUNT(accountId), {
            method: "PUT",
            payload: { clientIds },
            signed: true
        })
    }

    createUnitHoldersRegisterEntry = async (date: Date, accountId: string | number, vintage: string | number, unitsAcquiredOrRedeemed: number, unitPrice: number, audInOut: number): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.UNIT_HOLDERS_REGISTER, {
            method: "POST",
            payload: { date, accountId, vintage, unitsAcquiredOrRedeemed, unitPrice, audInOut },
            signed: true
        })
    }

    updateInvestorPortalOptions = async (maintenanceMode: string | number, soapboxTitle: string, soapboxBody: string): Promise<APIResponse> => {
        return await this.fetchBase(ENDPOINTS.INVESTOR_PORTAL_OPTIONS, {
            method: "PUT",
            payload: { maintenanceMode, soapboxTitle, soapboxBody },
            signed: true
        })
    }
}
