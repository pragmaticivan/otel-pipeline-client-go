// Copyright Lightstep Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pipelines

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/sdk/metric/sdkapi"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	metricglobal "go.opentelemetry.io/otel/metric/global"
	"go.opentelemetry.io/otel/sdk/metric/aggregator/histogram"
	controller "go.opentelemetry.io/otel/sdk/metric/controller/basic"
	"go.opentelemetry.io/otel/sdk/metric/export/aggregation"
	processor "go.opentelemetry.io/otel/sdk/metric/processor/basic"
	selector "go.opentelemetry.io/otel/sdk/metric/selector/simple"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding/gzip"
)

type (
	customTemporalitySelector struct{}
)

func (s customTemporalitySelector) TemporalityFor(desc *sdkapi.Descriptor, kind aggregation.Kind) aggregation.Temporality {
	if desc.InstrumentKind() == sdkapi.CounterInstrumentKind ||
		desc.InstrumentKind() == sdkapi.CounterObserverInstrumentKind ||
		desc.InstrumentKind() == sdkapi.HistogramInstrumentKind {
		return aggregation.DeltaTemporality
	}
	return aggregation.CumulativeTemporality
}

// CustomTemporalitySelector -
func CustomTemporalitySelector() aggregation.TemporalitySelector {
	return customTemporalitySelector{}
}

var (
	// This configures temporality to work correctly with New Relic for all metric types.
	// Counters and Histograms instruments use delta, everything else uses cumulative.
	temporalitySelector = CustomTemporalitySelector()
)

// NewMetricsPipeline -
func NewMetricsPipeline(c PipelineConfig) (func() error, error) {
	metricExporter, err := newMetricsExporter(c.Endpoint, c.Insecure, c.Headers)
	if err != nil {
		return nil, fmt.Errorf("failed to create metric exporter: %v", err)
	}

	period := controller.DefaultPeriod
	if c.ReportingPeriod != "" {
		period, err = time.ParseDuration(c.ReportingPeriod)
		if err != nil {
			return nil, fmt.Errorf("invalid metric reporting period: %v", err)
		}
		if period <= 0 {

			return nil, fmt.Errorf("invalid metric reporting period: %v", c.ReportingPeriod)
		}
	}
	pusher := controller.New(
		processor.NewFactory(
			selector.NewWithHistogramDistribution(
				histogram.WithExplicitBoundaries([]float64{1, 2, 5, 10, 20, 50}),
			),
			temporalitySelector,
		),
		controller.WithExporter(metricExporter),
		controller.WithResource(c.Resource),
		controller.WithCollectPeriod(period),
	)

	if err = pusher.Start(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to start controller: %v", err)
	}

	// if err = runtimeMetrics.Start(runtimeMetrics.WithMeterProvider(pusher)); err != nil {
	// 	return nil, fmt.Errorf("failed to start runtime metrics: %v", err)
	// }

	// if err = hostMetrics.Start(hostMetrics.WithMeterProvider(pusher)); err != nil {
	// 	return nil, fmt.Errorf("failed to start host metrics: %v", err)
	// }

	metricglobal.SetMeterProvider(pusher)
	return func() error {
		_ = pusher.Stop(context.Background())
		return metricExporter.Shutdown(context.Background())
	}, nil
}

func newMetricsExporter(endpoint string, insecure bool, headers map[string]string) (*otlpmetric.Exporter, error) {
	secureOption := otlpmetricgrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, ""))
	if insecure {
		secureOption = otlpmetricgrpc.WithInsecure()
	}
	return otlpmetric.New(
		context.Background(),
		otlpmetricgrpc.NewClient(
			secureOption,
			otlpmetricgrpc.WithEndpoint(endpoint),
			otlpmetricgrpc.WithHeaders(headers),
			otlpmetricgrpc.WithCompressor(gzip.Name),
		),
		otlpmetric.WithMetricAggregationTemporalitySelector(temporalitySelector),
	)
}
