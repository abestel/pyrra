package slo

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type MultiBurnRateAlert struct {
	Severity string
	Short    time.Duration
	Long     time.Duration
	For      time.Duration
	Factor   float64

	QueryShort string
	QueryLong  string
}

func (o Objective) Alerts() ([]MultiBurnRateAlert, error) {
	ws := Windows(time.Duration(o.Window))

	mbras := make([]MultiBurnRateAlert, len(ws))
	for i, w := range ws {
		queryShort, err := o.QueryBurnrate(w.Short, nil)
		if err != nil {
			return nil, err
		}
		queryLong, err := o.QueryBurnrate(w.Long, nil)
		if err != nil {
			return nil, err
		}

		mbras[i] = MultiBurnRateAlert{
			Severity:   string(w.Severity),
			Short:      w.Short,
			Long:       w.Long,
			For:        w.For,
			Factor:     w.Factor,
			QueryShort: queryShort,
			QueryLong:  queryLong,
		}
	}

	return mbras, nil
}

func (o Objective) Burnrates() (monitoringv1.RuleGroup, error) {
	sloName := o.Labels.Get(labels.MetricName)

	ws := Windows(time.Duration(o.Window))
	burnrates := burnratesFromWindows(ws)
	rules := make([]monitoringv1.Rule, 0, len(burnrates))

	totalMetric, err := o.TotalMetric()
	if err != nil {
		return monitoringv1.RuleGroup{
			Name:     sloName,
			Interval: monitoringDuration("30s"), // TODO: Increase or decrease based on availability target
			Rules:    rules,
		}, err
	}

	matchers := totalMetric.LabelMatchers
	groupingMap := o.GroupingMap()

	ruleLabels := o.commonRuleLabels(sloName)
	for _, m := range matchers {
		if m.Type == labels.MatchEqual && m.Name != labels.MetricName {
			ruleLabels[m.Name] = m.Value
		}
	}

	// Delete labels that are grouped as their value is part of the labels anyway
	for g := range groupingMap {
		delete(ruleLabels, g)
	}

	for _, br := range burnrates {
		expr, err := o.Burnrate(br)
		if err != nil {
			return monitoringv1.RuleGroup{
				Name:     sloName,
				Interval: monitoringDuration("30s"), // TODO: Increase or decrease based on availability target
				Rules:    rules,
			}, err
		}

		rules = append(rules, monitoringv1.Rule{
			Record: totalMetric.BurnrateName(br),
			Expr:   intstr.FromString(expr),
			Labels: ruleLabels,
		})
	}

	if o.Alerting.Disabled || !o.Alerting.Burnrates {
		return monitoringv1.RuleGroup{
			Name:     sloName,
			Interval: monitoringDuration("30s"), // TODO: Increase or decrease based on availability target
			Rules:    rules,
		}, nil
	}

	var alertMatchers []*labels.Matcher
	for _, m := range matchers {
		if m.Name == labels.MetricName {
			continue
		}

		if _, ok := groupingMap[m.Name]; !ok {
			if m.Type == labels.MatchRegexp || m.Type == labels.MatchNotRegexp {
				continue
			}
		}

		alertMatchers = append(alertMatchers, m)
	}

	alertMatchers = append(alertMatchers, &labels.Matcher{
		Type:  labels.MatchEqual,
		Name:  "slo",
		Value: sloName,
	})

	for _, w := range ws {
		alertLabels := o.commonRuleLabels(sloName)
		alertAnnotations := o.commonRuleAnnotations()
		for _, m := range matchers {
			if m.Type == labels.MatchEqual && m.Name != labels.MetricName {
				if _, ok := groupingMap[m.Name]; !ok { // only add labels that aren't grouped by
					alertLabels[m.Name] = m.Value
				}
			}
		}

		// Propagate useful SLO information to alerts' labels
		alertLabels["short"] = model.Duration(w.Short).String()
		alertLabels["long"] = model.Duration(w.Long).String()
		alertLabels["severity"] = string(w.Severity)
		alertLabels["exhaustion"] = o.Exhausts(w.Factor).String()

		expr, err := parser.ParseExpr(
			fmt.Sprintf(
				`metric{matchers="total"} > (%.f * (1-%s)) and errorMetric{matchers="errors"} > (%.f * (1-%s))`,
				w.Factor,
				strconv.FormatFloat(o.Target, 'f', -1, 64),
				w.Factor,
				strconv.FormatFloat(o.Target, 'f', -1, 64),
			))
		if err != nil {
			return monitoringv1.RuleGroup{
				Name:     sloName,
				Interval: monitoringDuration("30s"), // TODO: Increase or decrease based on availability target
				Rules:    rules,
			}, err
		}

		objectiveReplacer{
			metric:        totalMetric.BurnrateName(w.Short),
			matchers:      alertMatchers,
			errorMetric:   totalMetric.BurnrateName(w.Long),
			errorMatchers: alertMatchers,
		}.replace(expr)

		r := monitoringv1.Rule{
			Alert:       o.AlertName(),
			Expr:        intstr.FromString(expr.String()),
			For:         monitoringDuration(model.Duration(w.For).String()),
			Labels:      alertLabels,
			Annotations: alertAnnotations,
		}
		rules = append(rules, r)
	}

	// We only get here if alerting was not disabled
	return monitoringv1.RuleGroup{
		Name:     sloName,
		Interval: monitoringDuration("30s"), // TODO: Increase or decrease based on availability target
		Rules:    rules,
	}, nil
}

func (o Objective) BurnrateName(rate time.Duration) (string, error) {
	totalMetric, err := o.TotalMetric()
	if err != nil {
		return "", err
	}

	return totalMetric.BurnrateName(rate), nil
}

func (m Metric) BurnrateName(rate time.Duration) string {
	metricName := m.Name
	metricName = strings.TrimSuffix(metricName, "_total")
	metricName = strings.TrimSuffix(metricName, "_count")

	return fmt.Sprintf("%s:burnrate%s", metricName, model.Duration(rate))
}

func (o Objective) Burnrate(timerange time.Duration) (string, error) {
	totalMetric, err := o.TotalMetric()
	if err != nil {
		return "", err
	}

	replacer := objectiveReplacer{
		metric:   totalMetric.Name,
		matchers: totalMetric.LabelMatchers,
		grouping: o.GroupingLabels(),
		window:   timerange,
	}

	var query string

	switch o.IndicatorType() {
	case Ratio:
		query = `sum by (grouping) (rate(errorMetric{matchers="errors"}[1s])) / sum by (grouping) (rate(metric{matchers="total"}[1s]))`
		replacer.errorMetric = o.Indicator.Ratio.Errors.Name
		replacer.errorMatchers = o.Indicator.Ratio.Errors.LabelMatchers

	case Latency:
		query = `
			(
				sum by (grouping) (rate(metric{matchers="total"}[1s]))
				-
				sum by (grouping) (rate(errorMetric{matchers="errors"}[1s]))
			)
			/
			sum by (grouping) (rate(metric{matchers="total"}[1s]))
		`
		replacer.errorMetric = o.Indicator.Latency.Success.Name
		replacer.errorMatchers = o.Indicator.Latency.Success.LabelMatchers

	case LatencyNative:
		query = `1 - histogram_fraction(0,0.696969, rate(metric{matchers="total"}[1s]))`
		replacer.target = time.Duration(o.Indicator.LatencyNative.Latency).Seconds()

	case BoolGauge:
		query = `
			(
				sum by (grouping) (count_over_time(metric{matchers="total"}[1s]))
				-
				sum by (grouping) (sum_over_time(metric{matchers="total"}[1s]))
			)
			/
			sum by (grouping) (count_over_time(metric{matchers="total"}[1s]))
		`

	default:
		return "", fmt.Errorf("unsupported service level objective type for burnrate")
	}

	expr, err := parser.ParseExpr(query)
	if err != nil {
		return "", err
	}

	replacer.replace(expr)

	return expr.String(), nil
}

func sumName(metric string, window model.Duration) string {
	return fmt.Sprintf("%s:sum%s", metric, window)
}

func countName(metric string, window model.Duration) string {
	return fmt.Sprintf("%s:count%s", metric, window)
}

func increaseName(metric string, window model.Duration) string {
	metric = strings.TrimSuffix(metric, "_total")
	metric = strings.TrimSuffix(metric, "_count")
	metric = strings.TrimSuffix(metric, "_bucket")
	return fmt.Sprintf("%s:increase%s", metric, window)
}

func (o Objective) commonRuleLabels(sloName string) map[string]string {
	ruleLabels := map[string]string{
		"slo": sloName,
	}

	for _, label := range o.Labels {
		if strings.HasPrefix(label.Name, PropagationLabelsPrefix) {
			ruleLabels[strings.TrimPrefix(label.Name, PropagationLabelsPrefix)] = label.Value
		}
	}

	return ruleLabels
}

func (o Objective) commonRuleAnnotations() map[string]string {
	var annotations map[string]string
	if len(o.Annotations) > 0 {
		annotations = make(map[string]string)
		for key, value := range o.Annotations {
			if strings.HasPrefix(key, PropagationLabelsPrefix) {
				annotations[strings.TrimPrefix(key, PropagationLabelsPrefix)] = value
			}
		}
	}

	return annotations
}

func (o Objective) IncreaseRules() (monitoringv1.RuleGroup, error) {
	sloName := o.Labels.Get(labels.MetricName)

	countExpr := func() (parser.Expr, error) { // Returns a new instance of Expr with this query each time called
		return parser.ParseExpr(`sum by (grouping) (count_over_time(metric{matchers="total"}[1s]))`)
	}

	sumExpr := func() (parser.Expr, error) { // Returns a new instance of Expr with this query each time called
		return parser.ParseExpr(`sum by (grouping) (sum_over_time(metric{matchers="total"}[1s]))`)
	}

	increaseExpr := func() (parser.Expr, error) { // Returns a new instance of Expr with this query each time called
		return parser.ParseExpr(`sum by (grouping) (increase(metric{matchers="total"}[1s]))`)
	}

	absentExpr := func() (parser.Expr, error) {
		return parser.ParseExpr(`absent(metric{matchers="total"}) == 1`)
	}

	var rules []monitoringv1.Rule

	switch o.IndicatorType() {
	case Ratio:
		ruleLabels := o.commonRuleLabels(sloName)
		for _, m := range o.Indicator.Ratio.Total.LabelMatchers {
			if m.Type == labels.MatchEqual && m.Name != labels.MetricName {
				ruleLabels[m.Name] = m.Value
			}
		}

		groupingMap := map[string]struct{}{}
		for _, s := range o.Indicator.Ratio.Grouping {
			groupingMap[s] = struct{}{}
		}
		for _, s := range groupingLabels(
			o.Indicator.Ratio.Errors.LabelMatchers,
			o.Indicator.Ratio.Total.LabelMatchers,
		) {
			groupingMap[s] = struct{}{}
		}
		for _, m := range o.Indicator.Ratio.Total.LabelMatchers {
			if m.Type == labels.MatchRegexp || m.Type == labels.MatchNotRegexp {
				groupingMap[m.Name] = struct{}{}
			}
		}
		// Delete labels that are grouped, as their value is part of the recording rule anyway
		for g := range groupingMap {
			delete(ruleLabels, g)
		}

		grouping := make([]string, 0, len(groupingMap))
		for s := range groupingMap {
			grouping = append(grouping, s)
		}
		sort.Strings(grouping)

		expr, err := increaseExpr()
		if err != nil {
			return monitoringv1.RuleGroup{}, err
		}

		objectiveReplacer{
			metric:   o.Indicator.Ratio.Total.Name,
			matchers: o.Indicator.Ratio.Total.LabelMatchers,
			grouping: grouping,
			window:   time.Duration(o.Window),
		}.replace(expr)

		rules = append(rules, monitoringv1.Rule{
			Record: increaseName(o.Indicator.Ratio.Total.Name, o.Window),
			Expr:   intstr.FromString(expr.String()),
			Labels: ruleLabels,
		})

		alertLabels := make(map[string]string, len(ruleLabels)+1)
		for k, v := range ruleLabels {
			alertLabels[k] = v
		}
		// Add severity label for alerts
		alertLabels["severity"] = string(critical)

		// add the absent alert if configured
		if o.Alerting.Absent {
			expr, err = absentExpr()
			if err != nil {
				return monitoringv1.RuleGroup{}, err
			}

			objectiveReplacer{
				metric:   o.Indicator.Ratio.Total.Name,
				matchers: o.Indicator.Ratio.Total.LabelMatchers,
			}.replace(expr)

			rules = append(rules, monitoringv1.Rule{
				Alert: "SLOMetricAbsent",
				Expr:  intstr.FromString(expr.String()),
				For: monitoringDuration(model.Duration(
					(time.Duration(o.Window) / (28 * 24 * (60 / 2))).Round(time.Minute),
				).String()),
				Labels:      alertLabels,
				Annotations: o.commonRuleAnnotations(),
			})
		}

		if o.Indicator.Ratio.Total.Name != o.Indicator.Ratio.Errors.Name {
			expr, err := increaseExpr()
			if err != nil {
				return monitoringv1.RuleGroup{}, err
			}

			objectiveReplacer{
				metric:   o.Indicator.Ratio.Errors.Name,
				matchers: o.Indicator.Ratio.Errors.LabelMatchers,
				grouping: grouping,
				window:   time.Duration(o.Window),
			}.replace(expr)

			rules = append(rules, monitoringv1.Rule{
				Record: increaseName(o.Indicator.Ratio.Errors.Name, o.Window),
				Expr:   intstr.FromString(expr.String()),
				Labels: ruleLabels,
			})

			// add the absent alert if configured
			if o.Alerting.Absent {
				expr, err = absentExpr()
				if err != nil {
					return monitoringv1.RuleGroup{}, err
				}

				objectiveReplacer{
					metric:   o.Indicator.Ratio.Errors.Name,
					matchers: o.Indicator.Ratio.Errors.LabelMatchers,
				}.replace(expr)

				rules = append(rules, monitoringv1.Rule{
					Alert: "SLOMetricAbsent",
					Expr:  intstr.FromString(expr.String()),
					For: monitoringDuration(model.Duration(
						(time.Duration(o.Window) / (28 * 24 * (60 / 2))).Round(time.Minute),
					).String()),
					Labels:      alertLabels,
					Annotations: o.commonRuleAnnotations(),
				})
			}
		}
	case Latency:
		ruleLabels := o.commonRuleLabels(sloName)
		for _, m := range o.Indicator.Latency.Total.LabelMatchers {
			if m.Type == labels.MatchEqual && m.Name != labels.MetricName {
				ruleLabels[m.Name] = m.Value
			}
		}

		groupingMap := map[string]struct{}{}
		for _, s := range o.Indicator.Latency.Grouping {
			groupingMap[s] = struct{}{}
		}
		for _, s := range groupingLabels(
			o.Indicator.Latency.Success.LabelMatchers,
			o.Indicator.Latency.Total.LabelMatchers,
		) {
			groupingMap[s] = struct{}{}
		}
		for _, m := range o.Indicator.Latency.Total.LabelMatchers {
			if m.Type == labels.MatchRegexp || m.Type == labels.MatchNotRegexp {
				groupingMap[m.Name] = struct{}{}
			}
		}
		// Delete labels that are grouped, as their value is part of the recording rule anyway
		for g := range groupingMap {
			delete(ruleLabels, g)
		}

		grouping := make([]string, 0, len(groupingMap))
		for s := range groupingMap {
			grouping = append(grouping, s)
		}
		sort.Strings(grouping)

		expr, err := increaseExpr()
		if err != nil {
			return monitoringv1.RuleGroup{}, err
		}

		objectiveReplacer{
			metric:   o.Indicator.Latency.Total.Name,
			matchers: o.Indicator.Latency.Total.LabelMatchers,
			grouping: grouping,
			window:   time.Duration(o.Window),
		}.replace(expr)

		rules = append(rules, monitoringv1.Rule{
			Record: increaseName(o.Indicator.Latency.Total.Name, o.Window),
			Expr:   intstr.FromString(expr.String()),
			Labels: ruleLabels,
		})

		expr, err = increaseExpr()
		if err != nil {
			return monitoringv1.RuleGroup{}, err
		}

		objectiveReplacer{
			metric:   o.Indicator.Latency.Success.Name,
			matchers: o.Indicator.Latency.Success.LabelMatchers,
			grouping: grouping,
			window:   time.Duration(o.Window),
		}.replace(expr)

		var le string
		for _, m := range o.Indicator.Latency.Success.LabelMatchers {
			if m.Name == labels.BucketLabel {
				le = m.Value
				break
			}
		}
		ruleLabelsLe := map[string]string{labels.BucketLabel: le}
		for k, v := range ruleLabels {
			ruleLabelsLe[k] = v
		}

		rules = append(rules, monitoringv1.Rule{
			Record: increaseName(o.Indicator.Latency.Success.Name, o.Window),
			Expr:   intstr.FromString(expr.String()),
			Labels: ruleLabelsLe,
		})

		// add the absent alert if configured
		if o.Alerting.Absent {
			expr, err = absentExpr()
			if err != nil {
				return monitoringv1.RuleGroup{}, err
			}

			objectiveReplacer{
				metric:   o.Indicator.Latency.Total.Name,
				matchers: o.Indicator.Latency.Total.LabelMatchers,
			}.replace(expr)

			alertLabels := make(map[string]string, len(ruleLabels)+1)
			for k, v := range ruleLabels {
				alertLabels[k] = v
			}
			// Add severity label for alerts
			alertLabels["severity"] = string(critical)

			rules = append(rules, monitoringv1.Rule{
				Alert: "SLOMetricAbsent",
				Expr:  intstr.FromString(expr.String()),
				For: monitoringDuration(model.Duration(
					(time.Duration(o.Window) / (28 * 24 * (60 / 2))).Round(time.Minute),
				).String()),
				Labels:      alertLabels,
				Annotations: o.commonRuleAnnotations(),
			})

			expr, err = absentExpr()
			if err != nil {
				return monitoringv1.RuleGroup{}, err
			}

			objectiveReplacer{
				metric:   o.Indicator.Latency.Success.Name,
				matchers: o.Indicator.Latency.Success.LabelMatchers,
			}.replace(expr)

			alertLabelsLe := make(map[string]string, len(ruleLabelsLe)+1)
			for k, v := range ruleLabelsLe {
				alertLabelsLe[k] = v
			}
			// Add severity label for alerts
			alertLabelsLe["severity"] = string(critical)

			rules = append(rules, monitoringv1.Rule{
				Alert: "SLOMetricAbsent",
				Expr:  intstr.FromString(expr.String()),
				For: monitoringDuration(model.Duration(
					(time.Duration(o.Window) / (28 * 24 * (60 / 2))).Round(time.Minute),
				).String()),
				Labels:      alertLabelsLe,
				Annotations: o.commonRuleAnnotations(),
			})
		}
	case LatencyNative:
		ruleLabels := o.commonRuleLabels(sloName)
		for _, m := range o.Indicator.LatencyNative.Total.LabelMatchers {
			if m.Type == labels.MatchEqual && m.Name != labels.MetricName {
				ruleLabels[m.Name] = m.Value
			}
		}

		expr, err := parser.ParseExpr(`histogram_count(increase(metric{matchers="total"}[1s]))`)
		if err != nil {
			return monitoringv1.RuleGroup{}, err
		}

		objectiveReplacer{
			metric:   o.Indicator.LatencyNative.Total.Name,
			matchers: slices.Clone(o.Indicator.LatencyNative.Total.LabelMatchers),
			grouping: slices.Clone(o.Indicator.LatencyNative.Grouping),
			window:   time.Duration(o.Window),
		}.replace(expr)

		rules = append(rules, monitoringv1.Rule{
			Record: increaseName(o.Indicator.LatencyNative.Total.Name, o.Window),
			Expr:   intstr.FromString(expr.String()),
			Labels: ruleLabels,
		})

		expr, err = parser.ParseExpr(`histogram_fraction(0, 0.696969, increase(metric{matchers="total"}[1s])) * histogram_count(increase(metric{matchers="total"}[1s]))`)
		if err != nil {
			return monitoringv1.RuleGroup{}, err
		}

		latencySeconds := time.Duration(o.Indicator.LatencyNative.Latency).Seconds()
		objectiveReplacer{
			metric:   o.Indicator.LatencyNative.Total.Name,
			matchers: slices.Clone(o.Indicator.LatencyNative.Total.LabelMatchers),
			grouping: slices.Clone(o.Indicator.LatencyNative.Grouping),
			window:   time.Duration(o.Window),
			target:   latencySeconds,
		}.replace(expr)

		ruleLabels = maps.Clone(ruleLabels)
		ruleLabels[labels.BucketLabel] = fmt.Sprintf("%g", latencySeconds)

		rules = append(rules, monitoringv1.Rule{
			Record: increaseName(o.Indicator.LatencyNative.Total.Name, o.Window),
			Expr:   intstr.FromString(expr.String()),
			Labels: ruleLabels,
		})
	case BoolGauge:
		ruleLabels := o.commonRuleLabels(sloName)
		for _, m := range o.Indicator.BoolGauge.LabelMatchers {
			if m.Type == labels.MatchEqual && m.Name != labels.MetricName {
				ruleLabels[m.Name] = m.Value
			}
		}

		groupingMap := map[string]struct{}{}
		for _, s := range o.Indicator.BoolGauge.Grouping {
			groupingMap[s] = struct{}{}
		}
		for _, s := range o.Indicator.BoolGauge.LabelMatchers {
			groupingMap[s.Name] = struct{}{}
		}
		for _, m := range o.Indicator.BoolGauge.LabelMatchers {
			if m.Type == labels.MatchRegexp || m.Type == labels.MatchNotRegexp {
				groupingMap[m.Name] = struct{}{}
			}
		}
		// Delete labels that are grouped, as their value is part of the recording rule anyway
		for g := range groupingMap {
			delete(ruleLabels, g)
		}

		grouping := make([]string, 0, len(groupingMap))
		for s := range groupingMap {
			grouping = append(grouping, s)
		}
		sort.Strings(grouping)

		count, err := countExpr()
		if err != nil {
			return monitoringv1.RuleGroup{}, err
		}

		sum, err := sumExpr()
		if err != nil {
			return monitoringv1.RuleGroup{}, err
		}

		objectiveReplacer{
			metric:   o.Indicator.BoolGauge.Name,
			matchers: o.Indicator.BoolGauge.LabelMatchers,
			grouping: grouping,
			window:   time.Duration(o.Window),
		}.replace(count)

		objectiveReplacer{
			metric:   o.Indicator.BoolGauge.Name,
			matchers: o.Indicator.BoolGauge.LabelMatchers,
			grouping: grouping,
			window:   time.Duration(o.Window),
		}.replace(sum)

		rules = append(rules, monitoringv1.Rule{
			Record: countName(o.Indicator.BoolGauge.Name, o.Window),
			Expr:   intstr.FromString(count.String()),
			Labels: ruleLabels,
		})

		rules = append(rules, monitoringv1.Rule{
			Record: sumName(o.Indicator.BoolGauge.Name, o.Window),
			Expr:   intstr.FromString(sum.String()),
			Labels: ruleLabels,
		})

		if o.Alerting.Absent {
			expr, err := absentExpr()
			if err != nil {
				return monitoringv1.RuleGroup{}, err
			}

			objectiveReplacer{
				metric:   o.Indicator.BoolGauge.Name,
				matchers: o.Indicator.BoolGauge.LabelMatchers,
			}.replace(expr)

			alertLabels := make(map[string]string, len(ruleLabels)+1)
			for k, v := range ruleLabels {
				alertLabels[k] = v
			}
			// Add severity label for alerts
			alertLabels["severity"] = string(critical)

			rules = append(rules, monitoringv1.Rule{
				Alert: "SLOMetricAbsent",
				Expr:  intstr.FromString(expr.String()),
				For: monitoringDuration(model.Duration(
					(time.Duration(o.Window) / (28 * 24 * (60 / 2))).Round(time.Minute),
				).String()),
				Labels:      alertLabels,
				Annotations: o.commonRuleAnnotations(),
			})
		}
	}

	interval := o.RecordingRuleWindow()

	return monitoringv1.RuleGroup{
		Name:     sloName + "-increase",
		Interval: monitoringDuration(interval.String()),
		Rules:    rules,
	}, nil
}

func (o Objective) RecordingRuleWindow() model.Duration {
	week := 7 * 24 * time.Hour
	weeksInWindow := time.Duration(o.Window).Microseconds() / week.Microseconds()
	intervals := weeksInWindow + 1
	recordingRulePeriod := time.Duration(intervals) * 30 * time.Second
	return model.Duration(recordingRulePeriod)
}

type severity string

const (
	critical severity = "critical"
	warning  severity = "warning"
)

type Window struct {
	Severity severity
	For      time.Duration
	Long     time.Duration
	Short    time.Duration
	Factor   float64
}

func Windows(sloWindow time.Duration) []Window {
	// TODO: I'm still not sure if For, Long, Short should really be based on the 28 days ratio...

	round := time.Minute // TODO: Change based on sloWindow

	// long and short rates are calculated based on the ratio for 28 days.
	return []Window{{
		Severity: critical,
		For:      (sloWindow / (28 * 24 * (60 / 2))).Round(round), // 2m for 28d - half short
		Long:     (sloWindow / (28 * 24)).Round(round),            // 1h for 28d
		Short:    (sloWindow / (28 * 24 * (60 / 5))).Round(round), // 5m for 28d
		Factor:   14,                                              // error budget burn: 50% within a day
	}, {
		Severity: critical,
		For:      (sloWindow / (28 * 24 * (60 / 15))).Round(round), // 15m for 28d - half short
		Long:     (sloWindow / (28 * (24 / 6))).Round(round),       // 6h for 28d
		Short:    (sloWindow / (28 * 24 * (60 / 30))).Round(round), // 30m for 28d
		Factor:   7,                                                // error budget burn: 20% within a day / 100% within 5 days
	}, {
		Severity: warning,
		For:      (sloWindow / (28 * 24)).Round(round),       // 1h for 28d - half short
		Long:     (sloWindow / 28).Round(round),              // 1d for 28d
		Short:    (sloWindow / (28 * (24 / 2))).Round(round), // 2h for 28d
		Factor:   2,                                          // error budget burn: 10% within a day / 100% within 10 days
	}, {
		Severity: warning,
		For:      (sloWindow / (28 * (24 / 3))).Round(round), // 3h for 28d - half short
		Long:     (sloWindow / 7).Round(round),               // 4d for 28d
		Short:    (sloWindow / (28 * (24 / 6))).Round(round), // 6h for 28d
		Factor:   1,                                          // error budget burn: 100% until the end of sloWindow
	}}
}

func burnratesFromWindows(ws []Window) []time.Duration {
	dedup := map[time.Duration]bool{}
	for _, w := range ws {
		dedup[w.Long] = true
		dedup[w.Short] = true
	}
	burnrates := make([]time.Duration, 0, len(dedup))
	for duration := range dedup {
		burnrates = append(burnrates, duration)
	}

	sort.Slice(burnrates, func(i, j int) bool {
		return burnrates[i].Nanoseconds() < burnrates[j].Nanoseconds()
	})

	return burnrates
}

var ErrGroupingUnsupported = errors.New("objective with grouping not supported in generic rules")

func (o Objective) GenericRules() (monitoringv1.RuleGroup, error) {
	sloName := o.Labels.Get(labels.MetricName)
	var rules []monitoringv1.Rule

	ruleLabels := o.commonRuleLabels(sloName)

	rules = append(rules, monitoringv1.Rule{
		Record: "pyrra_objective",
		Expr:   intstr.FromString(strconv.FormatFloat(o.Target, 'f', -1, 64)),
		Labels: ruleLabels,
	})
	rules = append(rules, monitoringv1.Rule{
		Record: "pyrra_window",
		Expr:   intstr.FromInt32(int32(time.Duration(o.Window).Seconds())),
		Labels: ruleLabels,
	})

	prepareLabels := func(baseMatchers []*labels.Matcher, metricName string) []*labels.Matcher {
		matchers := cloneMatchers(baseMatchers)

		for _, m := range matchers {
			if m.Name == labels.MetricName {
				m.Value = metricName
				break
			}
		}

		matchers = append(matchers, &labels.Matcher{
			Type:  labels.MatchEqual,
			Name:  "slo",
			Value: o.Name(),
		})

		return matchers
	}

	appendRule := func(record string, expr parser.Expr, replacer objectiveReplacer) {
		replacer.replace(expr)

		rules = append(rules, monitoringv1.Rule{
			Record: record,
			Expr:   intstr.FromString(expr.String()),
			Labels: ruleLabels,
		})
	}

	if len(o.Grouping()) > 0 {
		return monitoringv1.RuleGroup{}, ErrGroupingUnsupported
	}

	switch o.IndicatorType() {
	case Ratio:
		availabilityExpr, availabilityErr := parser.ParseExpr(`1 - sum(errorMetric{matchers="errors"} or vector(0)) / sum(metric{matchers="total"})`)
		totalExpr, totalErr := parser.ParseExpr(`sum(metric{matchers="total"})`)
		errorsExpr, errorsErr := parser.ParseExpr(`sum(metric{matchers="total"} or vector(0))`)
		parseErrors := errors.Join(availabilityErr, totalErr, errorsErr)
		if parseErrors != nil {
			return monitoringv1.RuleGroup{}, parseErrors
		}

		// Availability
		totalIncreaseName := increaseName(o.Indicator.Ratio.Total.Name, o.Window)
		totalMatchers := prepareLabels(o.Indicator.Ratio.Total.LabelMatchers, totalIncreaseName)

		errorsIncreaseName := increaseName(o.Indicator.Ratio.Errors.Name, o.Window)
		errorMatchers := prepareLabels(o.Indicator.Ratio.Errors.LabelMatchers, errorsIncreaseName)

		appendRule("pyrra_availability", availabilityExpr, objectiveReplacer{
			metric:        totalIncreaseName,
			matchers:      totalMatchers,
			errorMetric:   errorsIncreaseName,
			errorMatchers: errorMatchers,
		})

		// Total
		appendRule("pyrra_requests_total", totalExpr, objectiveReplacer{
			metric:   o.Indicator.Ratio.Total.Name,
			matchers: o.Indicator.Ratio.Total.LabelMatchers,
		})

		// Errors
		appendRule("pyrra_errors_total", errorsExpr, objectiveReplacer{
			metric:   o.Indicator.Ratio.Errors.Name,
			matchers: o.Indicator.Ratio.Errors.LabelMatchers,
		})

	case Latency:
		availabilityExpr, availabilityErr := parser.ParseExpr(`sum(errorMetric{matchers="errors"} or vector(0)) / sum(metric{matchers="total"})`)
		totalExpr, totalErr := parser.ParseExpr(`sum(metric{matchers="total"})`)
		errorsExpr, errorsErr := parser.ParseExpr(`sum(metric{matchers="total"}) - sum(errorMetric{matchers="errors"})`)
		parseErrors := errors.Join(availabilityErr, totalErr, errorsErr)
		if parseErrors != nil {
			return monitoringv1.RuleGroup{}, parseErrors
		}

		// Availability
		metric := increaseName(o.Indicator.Latency.Total.Name, o.Window)
		matchers := prepareLabels(o.Indicator.Latency.Total.LabelMatchers, metric)
		matchers = append(matchers, &labels.Matcher{Type: labels.MatchEqual, Name: labels.BucketLabel, Value: ""})

		errorMetric := increaseName(o.Indicator.Latency.Success.Name, o.Window)
		errorMatchers := prepareLabels(o.Indicator.Latency.Success.LabelMatchers, errorMetric)

		appendRule("pyrra_availability", availabilityExpr, objectiveReplacer{
			metric:        metric,
			matchers:      matchers,
			errorMetric:   errorMetric,
			errorMatchers: errorMatchers,
			window:        time.Duration(o.Window),
		})

		// Total
		appendRule("pyrra_requests_total", totalExpr, objectiveReplacer{
			metric:   o.Indicator.Latency.Total.Name,
			matchers: o.Indicator.Latency.Total.LabelMatchers,
		})

		// Errors
		appendRule("pyrra_errors_total", errorsExpr, objectiveReplacer{
			metric:        o.Indicator.Latency.Total.Name,
			matchers:      o.Indicator.Latency.Total.LabelMatchers,
			errorMetric:   o.Indicator.Latency.Success.Name,
			errorMatchers: o.Indicator.Latency.Success.LabelMatchers,
		})

	case BoolGauge:
		availabilityExpr, availabilityErr := parser.ParseExpr(`sum(errorMetric{matchers="errors"}) / sum(metric{matchers="total"})`)
		totalExpr, totalErr := parser.ParseExpr(`sum(metric{matchers="total"})`)
		errorsExpr, errorsErr := parser.ParseExpr(`sum(metric{matchers="total"}) - sum(errorMetric{matchers="errors"})`)
		parseErrors := errors.Join(availabilityErr, totalErr, errorsErr)
		if parseErrors != nil {
			return monitoringv1.RuleGroup{}, parseErrors
		}

		// Availability
		totalMetric := countName(o.Indicator.BoolGauge.Metric.Name, o.Window)
		totalMatchers := prepareLabels(o.Indicator.BoolGauge.Metric.LabelMatchers, totalMetric)

		successMetric := sumName(o.Indicator.BoolGauge.Metric.Name, o.Window)
		successMatchers := prepareLabels(o.Indicator.BoolGauge.Metric.LabelMatchers, successMetric)

		appendRule("pyrra_availability", availabilityExpr, objectiveReplacer{
			metric:        totalMetric,
			matchers:      totalMatchers,
			errorMetric:   successMetric,
			errorMatchers: successMatchers,
		})

		// Total
		appendRule("pyrra_requests_total", totalExpr, objectiveReplacer{
			metric:   totalMetric,
			matchers: totalMatchers,
		})

		// Errors
		appendRule("pyrra_errors_total", errorsExpr, objectiveReplacer{
			metric:        totalMetric,
			matchers:      totalMatchers,
			errorMetric:   successMetric,
			errorMatchers: successMatchers,
		})
	}

	return monitoringv1.RuleGroup{
		Name:     sloName + "-generic",
		Interval: monitoringDuration("30s"),
		Rules:    rules,
	}, nil
}

func monitoringDuration(d string) *monitoringv1.Duration {
	md := monitoringv1.Duration(d)
	return &md
}
