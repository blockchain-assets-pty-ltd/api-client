import Web3 from "web3"

export const signMessageWithEthereumPrivateKey = async (message: string, privateKey: string) => {
    const web3 = new Web3()
    const signature = web3.eth.accounts.sign(message, privateKey)
    return signature
}
