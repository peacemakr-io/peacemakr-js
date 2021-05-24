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

python3 -m http.server 8082
```

Note: Sometimes browser needs to be hard refreshed to load the changes.

## RoadMap
- [ ] SignOnly and VerifyOnly
- [ ] Persistent storage
- [ ] Unit test
- [ ] Deployment
- [ ] CI/CD automation with github actions