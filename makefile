BINARY=IridiumSR

build-win:
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -o build/${BINARY}_windows_amd64.exe
build-darwin:
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o build/${BINARY}_darwin_amd64
build-linux:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o build/${BINARY}_linux_amd64
	
build-arm64:
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o build/${BINARY}_darwin_arm64
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -o build/${BINARY}_linux_arm64

pre-build:
	mkdir build
	cp ./config.json ./build/config.json
