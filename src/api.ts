import Module from "./corecrypto.js";

interface Contact {
    email: string,
    name: string,
    phone: string,
}

interface ApiKey {
    authorizedUseDomains: string[],
    creationTime: number,
    creator: Contact,
    key: string,
    orgId: string,
}

type KeyType = "ec" | "rsa";

interface PublicKey {
    creationTime: number,
    encoding: string, // always should be "pem"
    id: string,
    key: string,
    keyType: KeyType,
    owningClientId: string,
    owningOrgId: string,
}

interface OidcParam {
    clientId: string,
    url: string,
}

interface Org {
    apiKeys: ApiKey[],
    clientIds: string[],
    contacts: Contact[],
    cryptoConfigId: string,
    id: string,
    manualParams: PublicKey[],
    name: string,
    oidcParams: OidcParam[],
    stripeCustomerId: string,
}

interface TinyOrg {
    id: string,
    name: string,
}

type DigestAlgorithm =
    "Peacemakr.Digest.SHA_224"
    | "Peacemakr.Digest.SHA_256"
    | "Peacemakr.Digest.SHA_384"
    | "Peacemakr.Digest.SHA_512";
type EncryptionAlgorithm =
    "Peacemakr.Symmetric.CHACHA20_POLY1305"
    | "Peacemakr.Symmetric.AES_128_GCM"
    | "Peacemakr.Symmetric.AES_192_GCM"
    | "Peacemakr.Symmetric.AES_256_GCM";

interface UseDomain {
    collaboratingOrgs: TinyOrg[],
    creationTime: number,
    digestAlgorithm: DigestAlgorithm,
    encryptingPackagedCiphertextVersion: number,
    encryptionKeyIds: string[],
    endableKDSFallbackToCloud: boolean,
    id: string,
    name: string,
    ownerOrgId: string,
    requireSignedKeyDelivery: boolean,
    symmetricKeyDecryptionAllowed: boolean,
    symmetricKeyDecryptionUseTTL: number,
    symmetricKeyDerivationServiceId: string,
    symmetricKeyEncryptionAlg: EncryptionAlgorithm,
    symmetricKeyEncryptionAllowed: boolean,
    symmetricKeyEncryptionUseTTL: number,
    symmetricKeyInceptionTTL: number,
    symmetricKeyLength: number,
    symmetricKeyRetentionUseTTL: number,
}

interface CryptoConfig {
    clientKeyBitlength: number,
    clientKeyTTL: number,
    clientKeyType: KeyType,
    id: string,
    ownerOrgId: string,
    symmetricKeyUseDomainSelectorScheme: string,
    symmetricKeyUseDomains: UseDomain[],
}

interface Client {
    id: string,
    preferredPublicKeyId: string,
    publicKeys: PublicKey[],
    sdk: string,
}

interface EncryptedKey {
    keyIds: string[],
    keyLength: number,
    packagedCiphertext: string,
    symmetricKeyUseDomainId: string,
}

interface CiphertextAAD {
    cryptoKeyID: string,
    senderKeyID: string,
}

interface CiphertextConfig {
    // TODO
}

interface DeserializeResult {
    ciphertext: number, // uintptr_t
    config: CiphertextConfig,
}

interface Plaintext {
    data: string,
    aad: string,
}

interface DecryptResult {
    plaintext: Plaintext,
    needs_verify: boolean,
}

const randomElement = <T>(array: Array<T>): T => array[Math.floor(Math.random() * array.length)];

type Result<T, E> = Ok<T, E> | Err<T, E>;

const ok = <T, E>(value?: T): Result<T, E> => new Ok(value);
const err = <T, E>(error: E): Result<T, E> => new Err(error);
const errString = <T>(error: string): Result<T, Error> => new Err(new Error(error));
const isOk = <T, E>(r: Result<T, E>): boolean => r instanceof Ok

interface IResult<T, E> {
    ok(): boolean;

    err(): E | undefined;

    get<A>(f: (t: T) => A): Result<A, E>;

    andThen<U, F>(f: (t: T) => Promise<Result<U, F>>): Promise<Result<U, E | F>>;

    unwrap(f: (e: E) => void): T | undefined;
}

class Ok<T, E> implements IResult<T, E> {
    private readonly v: T;

    constructor(value?: T) {
        if (value) {
            this.v = value;
        }
    }

    value = (): T => this.v;

    ok(): boolean {
        return true;
    }

    err(): E | undefined {
        return undefined;
    }

    get<A>(f: (t: T) => A): Result<A, E> {
        return ok(f(this.v));
    }

    async andThen<U, F>(f: (t: T) => Promise<Result<U, F>>): Promise<Result<U, E | F>> {
        return f(this.v);
    }

    unwrap(f: (e: E) => void): T | undefined {
        return this.v
    }
}

class Err<T, E> {
    private readonly v: E;

    constructor(value: E) {
        this.v = value;
    }

    error = (): E => this.v;

    ok(): boolean {
        return false;
    }

    err(): E | undefined {
        return this.v
    }

    get<A>(f: (t: T) => A): Result<A, E> {
        return err(this.v);
    }

    async andThen<U, F>(f: (t: T) => Promise<Result<U, F>>): Promise<Result<U, E | F>> {
        return err(this.v);
    }

    unwrap(f: (e: E) => void): T | undefined {
        f(this.v);
        return undefined;
    }
}

class ApiClient {
    private readonly apiKey: string;
    private readonly baseURL: string;

    constructor(apiKey: string, baseURL: string = "https://api.peacemakr.io/api/v1") {
        this.apiKey = apiKey;
        this.baseURL = baseURL;
    }

    /**
     * Perform a GET request against this.baseURL + uri
     */
    private async get(uri: string): Promise<Result<Response, Error>> {
        try {
            const requestHeaders: HeadersInit = new Headers();
            requestHeaders.set("Authorization", this.apiKey);
            requestHeaders.set("Content-Type", "application/json");
            requestHeaders.set("Accept", "application/json, text/plain, */*");
            let res = await fetch(this.baseURL + uri, {
                headers: requestHeaders,
                method: "GET",
                mode: 'cors'
            });
            return ok(res);
        } catch (e) {
            return err(e);
        }
    }

    /**
     * Perform a POST request against this.baseURL + uri with body
     */
    private async post(uri: string, body: string): Promise<Result<Response, Error>> {
        try {
            const requestHeaders: HeadersInit = new Headers();
            requestHeaders.set("Authorization", this.apiKey);
            requestHeaders.set("Content-Type", "application/json");
            requestHeaders.set("Accept", "application/json, text/plain, */*");
            let res = await fetch(this.baseURL + uri, {
                headers: requestHeaders,
                method: "POST",
                mode: 'cors',
                body: body,
            });
            return ok(res);
        } catch (e) {
            return err(e);
        }
    }

    public async health(): Promise<Result<boolean, Error>> {
        let r = await this.get("/health");
        return r.andThen(async response => {
            return ok(response !== null && response.status === 200);
        });
    }

    public async getOrg(): Promise<Result<Org, Error>> {
        let r = await this.get("/org");
        return r.andThen(async response => {
            let org: Org = await response.json();
            return ok(org);
        });
    }

    public async getCryptoConfig(id: string): Promise<Result<CryptoConfig, Error>> {
        let r = await this.get(`/crypto/config/${encodeURIComponent(id)}`);
        return r.andThen(async response => {
            let cc: CryptoConfig = await response.json();
            return ok(cc);
        });
    }

    /**
     * Fills in the empty parameters in the client
     */
    public async addClient(c: Client): Promise<Result<Client, Error>> {
        let r = await this.post("/client", JSON.stringify(c));
        return r.andThen(async response => {
            let c: Client = await response.json();
            return ok(c);
        });
    }

    public async getKeys(clientKeyId: string, requiredKeyIds: string[]): Promise<Result<EncryptedKey[], Error>> {
        let url = `/crypto/symmetric/${encodeURIComponent(clientKeyId)}`;
        if (requiredKeyIds.length !== 0) {
            url += `?symmetricKeyIds=${encodeURIComponent(requiredKeyIds.toString())}`;
        }
        let r = await this.get(url);
        return r.andThen(async response => {
            let keys: EncryptedKey[] = await response.json();
            return ok(keys);
        });
    }

    public async getPublicKey(keyId: string): Promise<Result<PublicKey, Error>> {
        let r = await this.get(`/crypto/asymmetric/${encodeURIComponent(keyId)}`);
        return r.andThen(async response => {
            let pk: PublicKey = await response.json();
            return ok(pk);
        });
    }
}

type CryptoContext = Module.CryptoContext;
type Key = Module.Key;
type AsymmetricCipher = Module.AsymmetricCipher;
type SymmetricCipher = Module.SymmetricCipher;
type MessageDigestAlgorithm = Module.DigestAlgorithm;

class Crypto {
    private module: Module;
    private ctx: Module.CryptoContext
    private apiClient: ApiClient;

    /**
     * Why are these just class members instead of in the persister? Because the persister won't
     * survive a restart/page reload anyway - there's no real disk here. localStorage and sessionStorage are insecure.
     */

    private keypair: Key = undefined;
    private keypairAlg: AsymmetricCipher;
    private client: Client;
    private org_: Org | undefined = undefined;
    private cryptoConfig_: CryptoConfig | undefined = undefined;
    private keyCache: Map<string, Key>;

    constructor(apiKey: string) {
        Module().then(m => {
            this.module = m;
            this.ctx = m.CryptoContext.init();
        });

        this.apiClient = new ApiClient(apiKey);
        this.keyCache = new Map<string, Key>();
    }

    private bootstrapped(): boolean {
        return this.org_ !== undefined && this.cryptoConfig_ !== undefined;
    }

    private registered(): boolean {
        return this.keypair !== undefined && this.client !== undefined;
    }

    private async genKeyPair(): Promise<PublicKey> {
        if (!this.bootstrapped()) {
            await this.bootstrap();
        }

        let asymmetricCipher;
        let keyTy = (this.cryptoConfig_ as CryptoConfig).clientKeyType;
        let keyBitLen = (this.cryptoConfig_ as CryptoConfig).clientKeyBitlength;
        switch (keyTy) {
            case "ec":
                switch (keyBitLen) {
                    case 256:
                        asymmetricCipher = this.module.AsymmetricCipher.ECDH_P256;
                        break;
                    case 384:
                        asymmetricCipher = this.module.AsymmetricCipher.ECDH_P384;
                        break;
                    case 521:
                        asymmetricCipher = this.module.AsymmetricCipher.ECDH_P521;
                        break;
                }
                break;
            case "rsa":
                switch (keyBitLen) {
                    case 2048:
                        asymmetricCipher = this.module.AsymmetricCipher.RSA_2048;
                        break;
                    case 4096:
                        asymmetricCipher = this.module.AsymmetricCipher.RSA_4096;
                        break;
                }
        }

        let rng = new this.module.RandomDevice();
        this.keypair = this.module.Key.new_asymmetric(asymmetricCipher, this.module.SymmetricCipher.CHACHA20_POLY1305, rng);
        this.keypairAlg = asymmetricCipher;

        let pub = this.keypair.get_pub_pem();

        return {
            creationTime: Math.floor(Date.now() / 1000), // unix timestamp in seconds
            encoding: "pem",
            keyType: keyTy,
            key: pub,
            id: "",
            owningClientId: "",
            owningOrgId: ""
        };
    }

    private async bootstrap() {
        let ro = await this.apiClient.getOrg();
        ro.get(org => {
            this.org_ = org
        });

        let rc = await this.apiClient.getCryptoConfig((this.org_ as Org).cryptoConfigId);
        rc.get(cc => {
            this.cryptoConfig_ = cc
        });
    }

    private translateAlg(alg: EncryptionAlgorithm): SymmetricCipher {
        switch (alg) {
            case "Peacemakr.Symmetric.AES_128_GCM":
                return this.module.SymmetricCipher.AES_128_GCM;
            case "Peacemakr.Symmetric.AES_192_GCM":
                return this.module.SymmetricCipher.AES_192_GCM;
            case "Peacemakr.Symmetric.AES_256_GCM":
                return this.module.SymmetricCipher.AES_256_GCM;
            case "Peacemakr.Symmetric.CHACHA20_POLY1305":
                return this.module.SymmetricCipher.CHACHA20_POLY1305;
            default:
                return this.module.SymmetricCipher.CHACHA20_POLY1305;
        }
    }

    private translateDigest(dig: DigestAlgorithm): MessageDigestAlgorithm {
        switch (dig) {
            case "Peacemakr.Digest.SHA_224":
                return this.module.DigestAlgorithm.SHA_224;
            case "Peacemakr.Digest.SHA_256":
                return this.module.DigestAlgorithm.SHA_256;
            case "Peacemakr.Digest.SHA_384":
                return this.module.DigestAlgorithm.SHA_384;
            case "Peacemakr.Digest.SHA_512":
                return this.module.DigestAlgorithm.SHA_512;
            default:
                return this.module.DigestAlgorithm.SHA_256;
        }
    }

    private async getAsymmetricKey(keyId: string): Promise<Result<Key, Error>> {
        let out;
        if (this.keyCache.has(keyId)) {
            out = this.keyCache.get(keyId);
        } else {
            let pubkey = await this.apiClient.getPublicKey(keyId);
            let keyobj = pubkey.unwrap(err => console.log(err));
            out = this.module.Key.from_pem(this.module.SymmetricCipher.CHACHA20_POLY1305, (keyobj as PublicKey).key, "");
            this.keyCache.set(keyId, out);
        }
        return ok(out);
    }

    private async downloadKeys(keyIds?: string[]): Promise<Result<void, Error>> {
        let keys;
        if (keyIds) {
            keys = await this.apiClient.getKeys(this.client.preferredPublicKeyId, keyIds);
        } else {
            keys = await this.apiClient.getKeys(this.client.preferredPublicKeyId, []);
        }

        return await keys.andThen(async encryptedKeys => {
            for (let key of encryptedKeys) {
                let ciphertext = key.packagedCiphertext;
                let aadOnly: Plaintext = this.ctx.extract_unverified_aad(ciphertext);
                let aadObj: CiphertextAAD = JSON.parse(aadOnly.aad);
                let r = await this.getAsymmetricKey(aadObj.senderKeyID);
                let verifyKey: Key = r.unwrap(err => console.log(err));

                let decryptKey = this.keypair;
                if (this.keypairAlg === this.module.AsymmetricCipher.ECDH_P256 ||
                    this.keypairAlg === this.module.AsymmetricCipher.ECDH_P384 ||
                    this.keypairAlg === this.module.AsymmetricCipher.ECDH_P521) {
                    decryptKey = this.module.Key.ecdh_keygen(this.module.SymmetricCipher.CHACHA20_POLY1305, this.keypair, verifyKey);
                }

                let deser: DeserializeResult = this.ctx.deserialize(ciphertext);
                let decrypted: DecryptResult = this.ctx.decrypt(decryptKey, deser.ciphertext);
                if (decrypted.needs_verify) {
                    if (!this.ctx.verify(verifyKey, decrypted.plaintext, deser.ciphertext)) {
                        return errString("key verification failed");
                    }
                }

                let offset = 0;
                let keysAsBytes = atob(decrypted.plaintext.data);
                let cc: CryptoConfig = this.cryptoConfig_ as CryptoConfig;
                for (let keyid of key.keyIds) {
                    let useDomain = cc.symmetricKeyUseDomains.find(elt => elt.encryptionKeyIds.indexOf(keyid) !== -1);
                    if (!useDomain) {
                        return errString("Could not find appropriate use domain");
                    }

                    let cfg: SymmetricCipher = this.translateAlg(useDomain.symmetricKeyEncryptionAlg);
                    let currentKey: string = keysAsBytes.substring(offset, offset + key.keyLength);
                    this.keyCache.set(keyid, this.module.Key.from_bytes(cfg, currentKey));
                    offset += key.keyLength;
                }
            }
            return ok();
        });
    }

    private async getKey(keyId: string): Promise<Result<Key, Error>> {
        if (this.keyCache.has(keyId)) {
            return this.keyCache.get(keyId);
        }

        let download = await this.downloadKeys([keyId]);
        return download.get(_ => {
            return this.keyCache.get(keyId);
        });
    }

    async register() {
        await this.apiClient.health();

        if (!this.registered() || !this.bootstrapped()) {
            await this.bootstrap();
        } else if (this.registered()) {
            // Nothing to return, already registered
            return;
        }
        let pubkey = await this.genKeyPair();
        let c = await this.apiClient.addClient({
            id: "",
            preferredPublicKeyId: "",
            publicKeys: [pubkey],
            sdk: "js/0.0.1",
        });

        let r = c.get(client => {
            this.client = client;
        });
        if (!r.ok()) {
            console.log("failed to register new client: ", r.err())
        }
    }

    /**
     * Don't need to update client asymmetric keys, this client is short-lived
     */

    async sync() {
        await this.apiClient.health();
        // Just pull down the org and crypto config again
        await this.bootstrap();
        // And download all keys again
        await this.downloadKeys();
    }

    private validDomains(): UseDomain[] {
        return (this.cryptoConfig_ as CryptoConfig).symmetricKeyUseDomains.filter(elt => elt.symmetricKeyEncryptionAllowed);
    }

    async encrypt(data: string, useDomain?: string): Promise<Result<string, Error>> {
        // First choose a use domain
        let validDomains = this.validDomains();
        if (!validDomains) {
            return errString("No valid use domains");
        }

        let chosenDomain;
        if (useDomain) {
            chosenDomain = validDomains.find(elt => elt.name === useDomain);
        } else {
            chosenDomain = randomElement(validDomains);
        }

        if (!chosenDomain) {
            return errString("Chosen use domain was not in the set of valid domains");
        }

        let keyId: string = randomElement(chosenDomain.encryptionKeyIds);
        if (!this.keyCache.has(keyId)) {
            let r = await this.downloadKeys([keyId]);
            if (!r.ok()) {
                return err(r.err() as Error);
            }
        }
        let key: Key = this.keyCache.get(keyId);
        let digest = this.translateDigest(chosenDomain.digestAlgorithm);

        let aad: CiphertextAAD = {
            cryptoKeyID: keyId,
            senderKeyID: this.client.preferredPublicKeyId,
        }

        let plaintext: Plaintext = {
            data: data,
            aad: JSON.stringify(aad),
        }
        let rng = new this.module.RandomDevice();
        let encrypted = this.ctx.encrypt(key, plaintext, rng);
        if (encrypted === 0) { // returns nullptr on failure
            return errString("Encryption failed");
        }
        if (!this.ctx.sign(this.keypair, plaintext, digest, encrypted)) {
            return errString("Signing failed");
        }
        let serialized = this.ctx.serialize(digest, encrypted);
        if (serialized.length === 0) {
            return errString("Serialization failed");
        }

        // Returns a string
        return ok(serialized);
    }

    async decrypt(encrypted: string): Promise<Result<string, Error>> {
        if (!this.bootstrapped()) {
            return errString("not bootstrapped");
        }
        let aadOnly: Plaintext = this.ctx.extract_unverified_aad(encrypted);
        let aadObj: CiphertextAAD = JSON.parse(aadOnly.aad);
        let validDomains = this.validDomains();
        let useDomain = validDomains.find(elt => elt.encryptionKeyIds.find(id => id === aadObj.cryptoKeyID) !== undefined);
        if (!useDomain) {
            return errString("Could not find an appropriate use domain");
        }
        if (!useDomain.symmetricKeyDecryptionAllowed) {
            return errString("Use domain is not viable for decryption")
        }

        // Get the verify key
        let r = await this.getAsymmetricKey(aadObj.senderKeyID);
        let verifyKey: Key = r.unwrap(err => console.log(err));

        let key = await this.getKey(aadObj.cryptoKeyID);
        let deser: DeserializeResult = this.ctx.deserialize(encrypted);
        let decrypted: DecryptResult = this.ctx.decrypt(key, deser.ciphertext);
        if (decrypted.needs_verify && !this.ctx.verify(verifyKey, decrypted.plaintext, deser.ciphertext)) {
            return errString("Verification failed");
        }

        return ok(decrypted.plaintext.data);
    }

    // TODO: signOnly/verifyOnly

}

export {Crypto};
