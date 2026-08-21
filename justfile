default: clean build

clean:
    rm -rf ./oox

build:
	go build -C ./cmd/oox/ -o ../../oox

tidy:
  go mod tidy -v
  cd cmd/oox; go mod tidy

