import { Big } from "big.js"
import { DateTime } from "luxon"
import type { Account, Administrator, Asset, AssetBalance, AssetPrice, AssetSettings, AssetSnapshotsEntry, AssetSource, TaxLedgerEntry, AttributionCalculation, Bot, CashDistribution, Client, FeeCalculation, FeeCapitalisationsEntry, FinancialYear, FundMetricsEntry, InvestorPortalAccessLogEntry, InvestorPortalOptions, Job, Liability, ModificationLogEntry, TaxAttribution, TaxFileNumber, UnitHoldersRegisterEntry, VintageData, AccountPartition } from "@blockchain-assets-pty-ltd/shared"
import type { FundOverview } from "./client"

const bigOrNull = (val: any) => val === null ? null : Big(val)
const dateTime = (date: string) => DateTime.fromISO(date)

type Deserialiser<T> = (val: Record<string, any>) => T

export default class Deserialise {
    static Array<T>(arr: Record<string, any>[], deserialiser: Deserialiser<T>) {
        return arr.map(x => deserialiser(x))
    }

    static Administrator: Deserialiser<Administrator> = (val) => {
        const { id, firstName, lastName, email, ethereumAddress, telegramUsername } = val
        return { id, firstName, lastName, email, ethereumAddress, telegramUsername }
    }

    static Bot: Deserialiser<Bot> = (val) => {
        const { id, name, ethereumAddress, apiKey, readOnly } = val
        return { id, name, ethereumAddress, apiKey, readOnly }
    }

    static Asset: Deserialiser<Asset> = (val) => {
        const { assetName, assetSymbol, balance, price } = val
        return { assetName, assetSymbol, balance: bigOrNull(balance), price: bigOrNull(price) }
    }

    static AssetSettings: Deserialiser<AssetSettings> = (val) => {
        const { assetName, assetSymbol, manualBalance, manualPrice, displayRank, cmcId } = val
        return { assetName, assetSymbol, manualBalance: bigOrNull(manualBalance), manualPrice: bigOrNull(manualPrice), displayRank, cmcId }
    }

    static AssetPrice: Deserialiser<AssetPrice> = (val) => {
        const { assetName, price, lastUpdatedAt } = val
        return { assetName, price: Big(price), lastUpdatedAt: dateTime(lastUpdatedAt) }
    }

    static AssetBalance: Deserialiser<AssetBalance> = (val) => {
        const { assetName, sourceId, balance, lastUpdatedAt } = val
        return { assetName, sourceId, balance: Big(balance), lastUpdatedAt: dateTime(lastUpdatedAt) }
    }

    static AssetSource: Deserialiser<AssetSource> = (val) => {
        const { id, name, type, description, readBalances, address, network } = val
        return { id, name, type, description, readBalances, address, network }
    }

    static AssetSnapshotsEntry: Deserialiser<AssetSnapshotsEntry> = (val) => {
        const { date, assetName, balance, price } = val
        return { date: dateTime(date), assetName, balance: Big(balance), price: Big(price) }
    }

    static UnitHoldersRegisterEntry: Deserialiser<UnitHoldersRegisterEntry> = (val) => {
        const { date, vintage, accountId, type, unitsAcquiredOrRedeemed, unitPrice, fundsInOrOut } = val
        return { date: dateTime(date), vintage, type, accountId, unitsAcquiredOrRedeemed: Big(unitsAcquiredOrRedeemed), unitPrice: Big(unitPrice), fundsInOrOut: Big(fundsInOrOut) }
    }

    static Account: Deserialiser<Account> = (val) => {
        const { id, name, entityType, addressLine1, addressLine2, suburb, state, postcode, country, distributionReinvestmentPercentage, oldId, unitsHeld, netRemainingCapital, initialInvestmentDate, tfnProvided } = val
        return {
            id, name, entityType, addressLine1, addressLine2, suburb, state, postcode, country, oldId,
            distributionReinvestmentPercentage: Big(distributionReinvestmentPercentage),
            unitsHeld: unitsHeld === undefined ? undefined : bigOrNull(unitsHeld),
            netRemainingCapital: netRemainingCapital === undefined ? undefined : bigOrNull(netRemainingCapital),
            initialInvestmentDate: !initialInvestmentDate ? initialInvestmentDate : dateTime(initialInvestmentDate),
            tfnProvided
        }
    }

    static AccountPartition: Deserialiser<AccountPartition> = (val) => {
        const { accountId, order, units, averageUnitPrice, name } = val
        return { accountId: Number(accountId), order: Number(order), units: Big(units), averageUnitPrice: Big(averageUnitPrice), name }
    }

    static Client: Deserialiser<Client> = (val) => {
        const { id, firstName, lastName, email, ethereumAddress, lastAccessedAt, accessesInLast7Days, totalAccesses } = val
        return {
            id, firstName, lastName, email, ethereumAddress,
            lastAccessedAt: !lastAccessedAt ? lastAccessedAt : dateTime(lastAccessedAt),
            accessesInLast7Days, totalAccesses
        }
    }

    static FundMetricsEntry: Deserialiser<FundMetricsEntry> = (val) => {
        const { date, unitPrice, aum } = val
        return { date: dateTime(date), unitPrice: bigOrNull(unitPrice), aum: bigOrNull(aum) }
    }

    static InvestorPortalAccessLogEntry: Deserialiser<InvestorPortalAccessLogEntry> = (val) => {
        const { sessionStartedAt, clientId, lastActivityAt, deviceType, os, browser } = val
        return { sessionStartedAt: dateTime(sessionStartedAt), clientId, lastActivityAt: dateTime(lastActivityAt), deviceType, os, browser }
    }

    static InvestorPortalOptions: Deserialiser<InvestorPortalOptions> = (val) => {
        const { maintenanceMode, soapboxTitle, soapboxBody, soapboxHtml } = val
        return { maintenanceMode, soapboxTitle, soapboxBody, soapboxHtml }
    }

    static FundOverview: Deserialiser<FundOverview> = (val) => {
        const { lastUpdatedAt, unitPrice, aum, assets, historicalFundMetrics } = val
        return {
            lastUpdatedAt: dateTime(lastUpdatedAt), unitPrice: Big(unitPrice), aum: Big(aum),
            assets: this.Array(assets, this.Asset),
            historicalFundMetrics: this.Array(historicalFundMetrics, this.FundMetricsEntry)
        }
    }

    static ModificationLogEntry: Deserialiser<ModificationLogEntry> = (val) => {
        const { date, adminId, clientId, botId, data, signature } = val
        return { date: dateTime(date), adminId, clientId, botId, data, signature }
    }

    static FeeCapitalisationsEntry: Deserialiser<FeeCapitalisationsEntry> = (val) => {
        const { date, vintage, valueAtCapitalisationDate, managementFee, highWaterMark, performanceFee } = val
        return {
            date: dateTime(date),
            vintage,
            valueAtCapitalisationDate: Big(valueAtCapitalisationDate),
            managementFee: Big(managementFee),
            highWaterMark: Big(highWaterMark),
            performanceFee: Big(performanceFee)
        }
    }

    static VintageData: Deserialiser<VintageData> = (val) => {
        const {
            id,
            creationDate,
            uhrEntries,
            initialCapitalInvested,
            initialUnitsAcquired,
            unitsRemainingAtValuationDate,
            unitsRedeemedOnValuationDate,
            latestFcEntry,
            previousMoneyRedeemedOnValuationDate,
            previousNetValueBeforePF,
            previousNetValueAfterPF,
            previousHighWaterMark,
            wasPreviousPerformanceFeePaidOut,
            valueAtValuationDate,
            accruedManagementFeeGstExclusive,
            accruedManagementFeeGstInclusive,
            redeemedUnitsManagementFeeGstExclusive,
            redeemedUnitsManagementFeeGstInclusive,
            payableManagementFeeGstExclusive,
            payableManagementFeeGstInclusive,
            netValueBeforePF,
            highWaterMark,
            preTaxInvestmentReturn,
            benchmarkPortfolio,
            benchmarkReturnOnCapital,
            benchmarkInvestmentReturn,
            outPerformance,
            indicativePerformanceFeeGstExclusive,
            indicativePerformanceFeeGstInclusive,
            redeemedUnitsPerformanceFeeGstExclusive,
            redeemedUnitsPerformanceFeeGstInclusive,
            payablePerformanceFeeGstExclusive,
            payablePerformanceFeeGstInclusive,
            netValueAfterPF,
            unitsOutstandingAtBeginningOfNextValuationPeriod
        } = val
        return {
            id,
            creationDate: dateTime(creationDate),
            uhrEntries: this.Array(uhrEntries, this.UnitHoldersRegisterEntry),
            initialCapitalInvested: Big(initialCapitalInvested),
            initialUnitsAcquired: Big(initialUnitsAcquired),
            unitsRemainingAtValuationDate: Big(unitsRemainingAtValuationDate),
            unitsRedeemedOnValuationDate: Big(unitsRedeemedOnValuationDate),
            latestFcEntry: !latestFcEntry ? latestFcEntry : this.FeeCapitalisationsEntry(latestFcEntry),
            previousMoneyRedeemedOnValuationDate: Big(previousMoneyRedeemedOnValuationDate),
            previousNetValueBeforePF: Big(previousNetValueBeforePF),
            previousNetValueAfterPF: Big(previousNetValueAfterPF),
            previousHighWaterMark: Big(previousHighWaterMark),
            wasPreviousPerformanceFeePaidOut,
            valueAtValuationDate: Big(valueAtValuationDate),
            accruedManagementFeeGstExclusive: Big(accruedManagementFeeGstExclusive),
            accruedManagementFeeGstInclusive: Big(accruedManagementFeeGstInclusive),
            redeemedUnitsManagementFeeGstExclusive: Big(redeemedUnitsManagementFeeGstExclusive),
            redeemedUnitsManagementFeeGstInclusive: Big(redeemedUnitsManagementFeeGstInclusive),
            payableManagementFeeGstExclusive: Big(payableManagementFeeGstExclusive),
            payableManagementFeeGstInclusive: Big(payableManagementFeeGstInclusive),
            netValueBeforePF: Big(netValueBeforePF),
            highWaterMark: Big(highWaterMark),
            preTaxInvestmentReturn: Big(preTaxInvestmentReturn),
            benchmarkPortfolio: Big(benchmarkPortfolio),
            benchmarkReturnOnCapital: Big(benchmarkReturnOnCapital),
            benchmarkInvestmentReturn: Big(benchmarkInvestmentReturn),
            outPerformance: Big(outPerformance),
            indicativePerformanceFeeGstExclusive: Big(indicativePerformanceFeeGstExclusive),
            indicativePerformanceFeeGstInclusive: Big(indicativePerformanceFeeGstInclusive),
            redeemedUnitsPerformanceFeeGstExclusive: Big(redeemedUnitsPerformanceFeeGstExclusive),
            redeemedUnitsPerformanceFeeGstInclusive: Big(redeemedUnitsPerformanceFeeGstInclusive),
            payablePerformanceFeeGstExclusive: Big(payablePerformanceFeeGstExclusive),
            payablePerformanceFeeGstInclusive: Big(payablePerformanceFeeGstInclusive),
            netValueAfterPF: Big(netValueAfterPF),
            unitsOutstandingAtBeginningOfNextValuationPeriod: Big(unitsOutstandingAtBeginningOfNextValuationPeriod)
        }
    }

    static FeeCalculation: Deserialiser<FeeCalculation> = (val) => {
        const { valuationDate, aum, rates: { managementFee, benchmarkReturn, performanceFee, gst }, vintages } = val
        return {
            valuationDate: dateTime(valuationDate),
            aum: Big(aum),
            rates: {
                managementFee: Big(managementFee),
                benchmarkReturn: Big(benchmarkReturn),
                performanceFee: Big(performanceFee),
                gst: Big(gst)
            },
            vintages: this.Array(vintages, this.VintageData)
        }
    }

    static FinancialYear: Deserialiser<FinancialYear> = (val) => {
        const { startDate, endDate } = val
        return {
            startDate: dateTime(startDate),
            endDate: dateTime(endDate)
        }
    }

    static TaxAttribution: Deserialiser<TaxAttribution> = (val) => {
        const { discountedCapitalGains, otherCapitalGains, otherIncome } = val
        return {
            discountedCapitalGains: Big(discountedCapitalGains),
            otherCapitalGains: Big(otherCapitalGains),
            otherIncome: Big(otherIncome)
        }
    }

    static CashDistribution: Deserialiser<CashDistribution> = (val) => {
        const { cashRedeemed, cashReinvested, cashPaidOut } = val
        return {
            cashRedeemed: Big(cashRedeemed),
            cashReinvested: Big(cashReinvested),
            cashPaidOut: Big(cashPaidOut)
        }
    }

    static TaxLedgerEntry: Deserialiser<TaxLedgerEntry> = (val) => {
        const { date, accountId, discountedCapitalGains, otherCapitalGains, otherIncome, cashRedeemed, cashReinvested, cashPaidOut } = val
        return {
            date: dateTime(date),
            accountId: Number(accountId),
            ...this.TaxAttribution({ discountedCapitalGains, otherCapitalGains, otherIncome }),
            ...this.CashDistribution({ cashRedeemed, cashReinvested, cashPaidOut })
        }
    }

    static AttributionCalculation: Deserialiser<AttributionCalculation> = (val) => {
        const { date, taxPool, cashPool, streamedTax, attributions } = val
        return {
            date: dateTime(date),
            taxPool: this.TaxAttribution(taxPool),
            cashPool: Big(cashPool),
            streamedTax: streamedTax.map((s: any) => ({ accountId: s.accountId, ...this.TaxAttribution(s) })),
            attributions: this.Array(attributions, this.TaxLedgerEntry)
        }
    }

    static Job: Deserialiser<Job> = (val) => {
        const { id, type, parameters, progress, error, running, startDate, finishDate } = val
        return {
            id,
            type,
            parameters,
            progress,
            error,
            running,
            startDate: dateTime(startDate),
            finishDate: finishDate === null ? null : dateTime(finishDate)
        }
    }

    static Liability: Deserialiser<Liability> = (val) => {
        const { id, balance, description, openDate, closeDate } = val
        return {
            id,
            balance: Big(balance),
            description,
            openDate: dateTime(openDate),
            closeDate: !closeDate ? closeDate : dateTime(closeDate)
        }
    }

    static TaxFileNumber: Deserialiser<TaxFileNumber> = (val) => {
        const { taxFileNumber, accountId, clientId } = val
        return {
            taxFileNumber,
            accountId,
            clientId
        }
    }
}
