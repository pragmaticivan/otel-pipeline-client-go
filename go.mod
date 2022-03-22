module github.com/pragmaticivan/otel-pipeline-client-go

go 1.16

require (
	github.com/kr/text v0.2.0 // indirect
	github.com/sethvargo/go-envconfig v0.5.0
	github.com/stretchr/testify v1.7.1
	go.opentelemetry.io/contrib/instrumentation/host v0.30.0
	go.opentelemetry.io/contrib/instrumentation/runtime v0.30.0
	go.opentelemetry.io/contrib/propagators/b3 v1.5.0
	go.opentelemetry.io/contrib/propagators/ot v1.5.0
	go.opentelemetry.io/otel v1.5.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric v0.27.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v0.27.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.5.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.5.0
	go.opentelemetry.io/otel/metric v0.27.0
	go.opentelemetry.io/otel/sdk v1.5.0
	go.opentelemetry.io/otel/sdk/metric v0.27.0
	google.golang.org/grpc v1.45.0
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
