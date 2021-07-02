# peacemakr-js
Peacemakr Javascript SDK


## Setup
```
npm install -g typescript
```
## Compile and generate artifact
```
npm run build
```
The generated artifact will be at `dist/` folder.

## Run example
```
# replace insert-your-api-key-here in index.html

# we need to run the server on port 8082 for CORS to work.
python3 -m http.server 8082
```
Note: Sometimes browser needs to be hard refreshed to load the changes.

## Example Code

```js
// By default, JS SDK uses in-memory persister.
// *****WARNING*****: DO NOT USE LocalStoragePersister for any purpose other than testing locally on browser.
let persister = null;
const c = new Crypto("insert-your-api-key-here", persister);
await c.register();

await c.sync();

// encrypt(message, useDomain)
let encrypted = await c.encrypt("Hello!", "default");
console.log(encrypted);
encrypted.get(async e => {
    let decrypted = await c.decrypt(e);
    decrypted.get(d => console.log(d));
});

let signed = await c.signOnly("SIGNME");
console.log(signed);
signed.get(async e => {
    let verified = await c.verifyOnly(e);
    verified.get(d => console.log(d));
});
```


## RoadMap
- [x] SignOnly and VerifyOnly
- [x] Persistent storage
- [x] Rotate client asymmetric keys
- [x] Clean up error handling
- [ ] Unit test
- [ ] Deployment to NPM
- [x] CI/CD automation with github actions