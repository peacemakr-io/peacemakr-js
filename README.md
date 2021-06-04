# peacemakr-js
Peacemakr Javascript SDK


## Setup
```
npm install -g typescript
```
## Compile
```
pushd src && tsc --build && popd
```

## Run
```
# replace ApiKey in index.html

# we need to run the server on port 8082 for CORS to work.
python3 -m http.server 8082
```

Note: Sometimes browser needs to be hard refreshed to load the changes.

## RoadMap
- [x] SignOnly and VerifyOnly
- [x] Persistent storage
- [ ] Rotate client asymmetric keys
- [ ] Clean up error handling
- [ ] Unit test
- [ ] Deployment
- [ ] CI/CD automation with github actions