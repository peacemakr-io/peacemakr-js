<p align="center">
  <br>
    <img src="https://admin.peacemakr.io/p_logo.png" width="150"/>
  <br>
</p>

# Peacemakr E2E-Encryption JavaScript SDK
[![CircleCI](https://circleci.com/gh/peacemakr-io/peacemakr-go-sdk/tree/master.svg?style=svg&circle-token=a5e0dd516384638b6e97cd79c7963d8081873df2)](https://circleci.com/gh/peacemakr-io/peacemakr-go-sdk/tree/master)

Peacemakr's E2E-Encryption SDK simplifies your data security with E2E-Encryption service and automated key lifecycle management.

You can easily encrypt your data without worrying about backward compatibility, cross platform portability, or changing security requirements.

Our Zero-Trust capability allows you to customize your security strength to meet the highest standard without having to place your trust in Peacemakr as we don’t have the capacity to get your keys and decrypt your data.

We take security and trust very seriously. If you believe you have found a security issue, please responsibly disclose by [contacting us](mailto:security@peacemakr.io).


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
# replace ApiKey in index.html

# we need to run the server on port 8082 for CORS to work.
python3 -m http.server 8082
```

Note: Sometimes browser needs to be hard refreshed to load the changes.

## RoadMap
- [x] SignOnly and VerifyOnly
- [x] Persistent storage
- [x] Rotate client asymmetric keys
- [x] Clean up error handling
- [ ] Unit test
- [ ] Deployment to NPM
- [x] CI/CD automation with github actions
