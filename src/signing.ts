import Web3 from "web3"

export const signMessageWithEthereumPrivateKey = async (message: string, privateKey: string) => {
    const web3 = new Web3()
    const address = web3.eth.accounts.wallet.add(privateKey).address
    const signature = await web3.eth.sign(message, address)

    return signature
}
