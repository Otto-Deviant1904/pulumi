module l2-raw-string-bytes

go 1.25

require (
	github.com/pulumi/pulumi/sdk/v3 v3.30.0
	example.com/pulumi-bytesink/sdk/go/v47 v47.0.0
	example.com/pulumi-bytesource/sdk/go/v46 v46.0.0
)

replace example.com/pulumi-bytesink/sdk/go/v47 => /ROOT/artifacts/example.com_pulumi-bytesink_sdk_go_v47

replace example.com/pulumi-bytesource/sdk/go/v46 => /ROOT/artifacts/example.com_pulumi-bytesource_sdk_go_v46

replace github.com/pulumi/pulumi/sdk/v3 => /ROOT/artifacts/github.com_pulumi_pulumi_sdk_v3
