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
    unitPrice: Big
    aum: Big
    assets: Asset[]
    historicalFundMetrics: FundMetricsEntry[]
}
