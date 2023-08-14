import { Web3 } from "web3"

export const signMessageWithEthereumPrivateKey = (message: string, privateKey: string): string => {
    const web3 = new Web3("http://") // Fake URL suppresses 'no provider' warning.
    const signResult = web3.eth.accounts.sign(message, "0x" + privateKey)
    return signResult.signature
}
