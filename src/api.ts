import Module from "./corecrypto.js";
import {Persister} from "./persister";

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

    public async addClientPublicKey(clientId: string, pubkey: PublicKey): Promise<Result<PublicKey, Error>> {
        let r = await this.post(`/client/${encodeURIComponent(clientId)}/addPublicKey`, JSON.stringify(pubkey));

        return r.andThen(async response => {
            let pk: PublicKey = await response.json();
            return ok(pk);
        })
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

interface PersistedSymmetricKey {
    key: string,
    cipher: EncryptionAlgorithm,
}

const OrgPersisterKey = "io.peacemakr.org";
const CryptoConfigPersisterKey = "io.peacemakr.crypto_config";
const ClientPersisterKey = "io.peacemakr.client";
const PrivPersisterKey = "io.peacemakr.priv";

class Crypto {
    private module: Module;
    private ctx: CryptoContext
    private apiClient: ApiClient;

    private keypair?: Key;
    private keyCreationTime: TimeRanges;
    private keypairAlg: AsymmetricCipher;
    private client: Client;
    private org_?: Org;
    private cryptoConfig_?: CryptoConfig;
    private keyCache: Map<string, Key>;

    private storage: Persister | null;

    constructor(apiKey: string, storage: Persister | null) {
        this.apiClient = new ApiClient(apiKey);
        this.keyCache = new Map<string, Key>();

        this.storage = storage;

        Module().then(m => {
            this.module = m;
            this.ctx = m.CryptoContext.init();

            if (this.storage != null) {
                if (this.storage.exists(OrgPersisterKey)) {
                    this.org_ = JSON.parse(this.storage.get(OrgPersisterKey));
                }
                if (this.storage.exists(CryptoConfigPersisterKey)) {
                    this.cryptoConfig_ = JSON.parse(this.storage.get(CryptoConfigPersisterKey));
                }
                if (this.storage.exists(ClientPersisterKey)) {
                    this.client = JSON.parse(this.storage.get(ClientPersisterKey));
                }
                if (this.storage.exists(PrivPersisterKey)) {
                    let priv = this.storage.get(PrivPersisterKey);
                    this.keypair = this.module.Key.from_bytes(this.module.SymmetricCipher.CHACHA20_POLY1305, priv);
                }
            }
        });
    }

    private bootstrapped(): boolean {
        return this.org_ != null && this.cryptoConfig_ != null;
    }

    private registered(): boolean {
        return this.keypair != null && this.client != null;
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

        if (this.storage) {
            let priv = this.keypair.get_priv_pem();
            this.storage.set(PrivPersisterKey, priv);
        }

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

    /**
     * returns true if current config is not null and config it out of date
     * @param newConfig
     * @returns boolean
     */
     private isCurrentCryptoConfigLatest(newConfig: CryptoConfig): boolean {
        if (this.cryptoConfig_) {
            // TODO: Add check for TTL
            if (newConfig.clientKeyBitlength !== (this.cryptoConfig_ as CryptoConfig).clientKeyBitlength ||
                newConfig.clientKeyType !== (this.cryptoConfig_ as CryptoConfig).clientKeyType) {
                        return false;
                    }
        }
        return true;
    }
    private async isCryptoConfigLatest(): Promise<boolean> {
        if (!this.org_ || !this.cryptoConfig_) {
            return false;
        }
        let latest = true;
        let rc = await this.apiClient.getCryptoConfig((this.org_ as Org).cryptoConfigId);
        let res = rc.get(cc => {
            latest = this.isCurrentCryptoConfigLatest(cc);
        });
        return latest;
    }

    private async bootstrap(): Promise<Boolean> {
        let latest = false;
        let ro = await this.apiClient.getOrg();
        let res = ro.get(org => {
            this.org_ = org
        });
        if (!res.ok()) {
            return true;
        }
        let rc = await this.apiClient.getCryptoConfig((this.org_ as Org).cryptoConfigId);
        res = rc.get(cc => {
            latest = this.isCurrentCryptoConfigLatest(cc);
            this.cryptoConfig_ = cc
        });
        if (!res.ok()) {
            return true;
        }

        if (this.storage) {
            this.storage.set(OrgPersisterKey, JSON.stringify(this.org_));
            this.storage.set(CryptoConfigPersisterKey, JSON.stringify(this.cryptoConfig_));
        }

        return latest;
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
        } else if (this.storage != null && this.storage.exists(keyId)) {
            // This is a public key so we can get the pem and do from_bytes
            let pem = this.storage.get(keyId);
            out = this.module.Key.from_pem(this.module.SymmetricCipher.CHACHA20_POLY1305, pem, "");
            this.keyCache.set(keyId, out);
        } else {
            let pubkey = await this.apiClient.getPublicKey(keyId);
            let e = pubkey.get(pk => {
                out = this.module.Key.from_pem(this.module.SymmetricCipher.CHACHA20_POLY1305, pk.key, "");
                if (this.storage) {
                    this.storage.set(keyId, pk.key);
                }
                this.keyCache.set(keyId, out);
            });
            if (!e.ok()) {
                return e;
            }
        }
        return ok(out);
    }

    private static keyFromB64(str: string): Uint8Array {
        let keysAsInts = atob(str);
        const keyByteArray = new Array(keysAsInts.length);
        for (let i = 0; i < keysAsInts.length; i++) {
            keyByteArray[i] = keysAsInts.charCodeAt(i);
        }
        return new Uint8Array(keyByteArray);
    }

    private static keyToB64(k: Uint8Array): string {
        return btoa(String.fromCharCode.apply(null, k));
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
                let asymmKey = await this.getAsymmetricKey(aadObj.senderKeyID);
                let e = asymmKey.get(verifyKey => {
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
                    const keysAsBytes = Crypto.keyFromB64(decrypted.plaintext.data);
                    let cc: CryptoConfig = this.cryptoConfig_ as CryptoConfig;
                    for (let keyid of key.keyIds) {
                        let useDomain = cc.symmetricKeyUseDomains.find(elt => elt.encryptionKeyIds.indexOf(keyid) !== -1);
                        if (!useDomain) {
                            return errString("Could not find appropriate use domain");
                        }

                        let cfg: SymmetricCipher = this.translateAlg(useDomain.symmetricKeyEncryptionAlg);
                        let currentKey = keysAsBytes.slice(offset, offset + key.keyLength);
                        if (this.storage) {
                            let storageKey: PersistedSymmetricKey = {
                                key: Crypto.keyToB64(currentKey),
                                cipher: useDomain.symmetricKeyEncryptionAlg,
                            }
                            this.storage.set(keyid, JSON.stringify(storageKey));
                        }
                        this.keyCache.set(keyid, this.module.Key.from_bytes(cfg, currentKey));
                        offset += key.keyLength;
                    }
                    return ok();
                });
                if (!e.ok()) {
                    return e;
                }
            }
            return ok();
        });
    }

    private async getKey(keyId: string, noDownload: boolean = false): Promise<Result<Key, Error>> {
        if (this.keyCache.has(keyId)) {
            return ok(this.keyCache.get(keyId));
        } else if (this.storage != null && this.storage.exists(keyId)) {
            let storageKey: PersistedSymmetricKey = JSON.parse(this.storage.get(keyId));
            let keyBytes = Crypto.keyFromB64(storageKey.key);
            let outKey = this.module.Key.from_bytes(this.translateAlg(storageKey.cipher), keyBytes);
            this.keyCache.set(keyId, outKey);
            return ok(outKey);
        }

        if (!noDownload) {
            let download = await this.downloadKeys([keyId]);
            if (!download.ok()) {
                return err(download.err() as Error);
            }
        }

        return this.getKey(keyId, true);
    }

    private async rotateAsymmetricKeys(): Promise<Result<void, Error>> {
        if (!this.registered() || !this.bootstrapped()) {
            await this.bootstrap();
        }

        let pubkey: PublicKey = await this.genKeyPair();
        let r = await this.apiClient.addClientPublicKey(this.client.id, pubkey);

        let rc = r.get(pubkey => {
            this.client.preferredPublicKeyId = pubkey.id;
            this.client.publicKeys.push(pubkey);
        });
        if (!rc.ok()) {
            return rc;
        }
        return ok();
    }

    async register(): Promise<Result<void, Error>> {
        await this.apiClient.health();

        // check persisted cryptoConfig is update to date. if it's not, we should refetch and regenerate keys.
        let isCryptoConfigUpToDate = await this.isCryptoConfigLatest();
        if (!this.registered() || !this.bootstrapped() || !isCryptoConfigUpToDate) {
            await this.bootstrap();
        } else if (this.registered()) {
            // Nothing to return, already registered
            return ok();
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
            return r;
        }

        if (this.storage) {
            this.storage.set(ClientPersisterKey, JSON.stringify(this.client));
        }
        return ok();
    }

    async sync(): Promise<Result<void, Error>> {
        await this.apiClient.health();

        let isCryptoConfigLatest = await this.bootstrap();
        if (!isCryptoConfigLatest) {
            // rotate the asymmetric keypair
            let r = await this.rotateAsymmetricKeys();
            if (!r.ok()) {
                return r;
            }
        }
        // And download all keys again
        await this.downloadKeys();
        return ok();
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
            chosenDomain = validDomains.find(elt => elt.name === useDomain || elt.id === useDomain);
        } else {
            chosenDomain = randomElement(validDomains);
        }

        if (!chosenDomain) {
            return errString("Chosen use domain was not in the set of valid domains");
        }

        let keyId: string = randomElement(chosenDomain.encryptionKeyIds);
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

        let k: Key = await this.getKey(keyId);
        return k.get(key => {
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
            return serialized;
        });
    }

    async decrypt(encrypted: string): Promise<Result<string, Error>> {
        if (!this.registered || !this.bootstrapped()) {
            return errString("not registered or bootstrapped");
        }
        let aadOnly: Plaintext = this.ctx.extract_unverified_aad(encrypted);
        let aadObj: CiphertextAAD = JSON.parse(aadOnly.aad);
        let validDomains = this.validDomains();
        let useDomain = validDomains.find(elt => elt.encryptionKeyIds.find(id => id === aadObj.cryptoKeyID) != null);
        if (!useDomain) {
            return errString("Could not find an appropriate use domain");
        }
        if (!useDomain.symmetricKeyDecryptionAllowed) {
            return errString("Use domain is not viable for decryption")
        }

        let deser: DeserializeResult = this.ctx.deserialize(encrypted);
        let k: Key = await this.getKey(aadObj.cryptoKeyID);
        return await k.get(async key => {
            let decrypted: DecryptResult = this.ctx.decrypt(key, deser.ciphertext);
            if (decrypted.needs_verify) {
                // Get the verify key
                let r = await this.getAsymmetricKey(aadObj.senderKeyID);
                let v = r.get(verifyKey => {
                    if (!this.ctx.verify(verifyKey, decrypted.plaintext, deser.ciphertext)) {
                        return errString("Verification failed");
                    }
                    return ok();
                });
                if (!v.ok()) {
                    return v;
                }
            }

            return ok(decrypted.plaintext.data);
        });
    }

    async signOnly(message: string): Promise<Result<string, Error>> {
        if (!this.registered() || !this.bootstrapped()) {
            return errString("not registered or bootstrapped");
        }

        if (!message || message.length === 0) {
            return errString("Cannot sign empty input");
        }

        let aad: CiphertextAAD = {
            cryptoKeyID: "",
            senderKeyID: this.client.preferredPublicKeyId,
        }
        let plaintext: Plaintext = {
            data: message,
            aad: JSON.stringify(aad),
        }
        let blob = this.ctx.get_plaintext_blob(plaintext);
        if (!this.ctx.sign(this.keypair, plaintext, this.module.DigestAlgorithm.SHA_256, blob)) {
            return errString("Signing failed");
        }
        let serialized = this.ctx.serialize(this.module.DigestAlgorithm.SHA_256, blob);
        return ok(serialized);
    }


    async verifyOnly(signedBlob: string): Promise<Result<string, Error>> {
        if (!this.registered() || !this.bootstrapped()) {
            return errString("not registered or bootstrapped");
        }

        if (!signedBlob || signedBlob.length === 0) {
            return errString("Cannot verify empty input");
        }

        let deserialized = this.ctx.deserialize(signedBlob);
        let plaintext = this.ctx.extract_plaintext_blob(deserialized.ciphertext);
        let aadOnly: Plaintext = this.ctx.extract_unverified_aad(signedBlob);
        let aadObj: CiphertextAAD = JSON.parse(aadOnly.aad);
        let r = await this.getAsymmetricKey(aadObj.senderKeyID);
        return r.get(verifyKey => {
            if (!this.ctx.verify(verifyKey, plaintext, deserialized.ciphertext)) {
                return errString("key verification failed");
            }

            return plaintext.data;
        });
    }

}

export {Crypto};
