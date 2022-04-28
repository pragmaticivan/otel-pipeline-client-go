module github.com/pragmaticivan/otel-pipeline-client-go

go 1.16

require (
	github.com/kr/text v0.2.0 // indirect
	github.com/sethvargo/go-envconfig v0.6.0
	github.com/stretchr/testify v1.7.1
	go.opentelemetry.io/contrib/instrumentation/host v0.31.0
	go.opentelemetry.io/contrib/instrumentation/runtime v0.31.0
	go.opentelemetry.io/contrib/propagators/b3 v1.6.0
	go.opentelemetry.io/contrib/propagators/ot v1.6.0
	go.opentelemetry.io/otel v1.6.3
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric v0.29.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v0.29.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.6.3
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.6.3
	go.opentelemetry.io/otel/metric v0.29.0
	go.opentelemetry.io/otel/sdk v1.6.3
	go.opentelemetry.io/otel/sdk/metric v0.29.0
	google.golang.org/grpc v1.46.0
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
