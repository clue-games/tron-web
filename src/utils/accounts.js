import { Entropy, charset64 } from 'entropy-string';
import { byteArray2hexStr } from './bytes';
import { 
    getBase58CheckAddress,
    genPriKeyWithEntropy,
    getAddressFromPriKey,
    getPubKeyFromPriKey
} from './crypto';

const entropy = new Entropy({ charset: charset64 });
const string = entropy.token();

export function generateAccount() {
    const priKeyBytes = genPriKeyWithEntropy(string);
    const pubKeyBytes = getPubKeyFromPriKey(priKeyBytes);
    const addressBytes = getAddressFromPriKey(priKeyBytes);
    
    const privateKey = byteArray2hexStr(priKeyBytes);
    const publicKey = byteArray2hexStr(pubKeyBytes);

    return {
        privateKey,
        publicKey,
        address: {
            base58: getBase58CheckAddress(addressBytes),
            hex: byteArray2hexStr(addressBytes)
        }
    }
}
