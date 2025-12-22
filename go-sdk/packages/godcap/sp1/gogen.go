package sp1

// Dependencies:
// * protoc: https://github.com/protocolbuffers/protobuf/releases
// * protoc-gen-go: `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest`
// * protoc-gen-go-grpc: `go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest`

//go:generate rm -fr sp1_proto
//go:generate protoc --proto_path=proto --go_out . --go-grpc_out . network.proto artifact.proto
