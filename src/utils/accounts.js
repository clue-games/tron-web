import { subtle } from 'isomorphic-webcrypto';
import { byteArray2hexStr } from './bytes';
import { 
    getBase58CheckAddress,
    genPriKeyWithEntropy,
    getAddressFromPriKey,
    getPubKeyFromPriKey
} from './crypto';


export async function generateAccount() {
    const string = await subtle.generateKey();

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
