package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"

	"github.com/cenab/cinderlock/internal/spec"
)

type Domain struct {
	Name   string
	Status string
}
type view struct {
	Run     spec.RunResult
	Domains []Domain
	Next    string
}

func Render(w io.Writer, run spec.RunResult) error {
	v := view{Run: run, Domains: []Domain{}}
	for _, name := range []string{"integrity", "readiness", "workflow", "recovery"} {
		status := run.Domains[name]
		if status == "" {
			status = "not_tested"
		}
		v.Domains = append(v.Domains, Domain{Name: name, Status: strings.ReplaceAll(status, "_", " ")})
	}
	switch run.State {
	case "needs_reconciliation":
		v.Next = "Inspect the declared reconciliation evidence before starting another mutation. Do not repeat an uncertain migration."
	case "failed", "recovery_failed":
		v.Next = "Inspect the failed operation and generate a supported recovery plan. Recovery requires separate authorization."
	case "succeeded":
		v.Next = "Retain this result and required recovery material under the site's retention policy."
	case "recovered":
		v.Next = "This records recovery to the named state, not success of the attempted upgrade."
	default:
		v.Next = "Query the durable run state before continuing. Unperformed required checks cannot establish acceptance."
	}
	t, err := template.New("report").Funcs(template.FuncMap{"number": observationNumber, "assessment": observationAssessment}).Parse(reportTemplate + observationTemplate)
	if err != nil {
		return err
	}
	return t.Execute(w, v)
}

func JSON(w io.Writer, run spec.RunResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(run)
}

func Markdown(w io.Writer, run spec.RunResult) error {
	escape := func(s string) string {
		return strings.NewReplacer("\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "!", "\\!", "\n", " ", "\r", " ", "|", "\\|", "<", "&lt;", ">", "&gt;").Replace(s)
	}
	sourceLine := ""
	if run.SourceRun != "" {
		sourceLine = fmt.Sprintf("\nSource run: `%s`\n", escape(run.SourceRun))
	}
	if _, err := fmt.Fprintf(w, "Cinderlock run `%s`\n\nAcceptance: **%s** · State: **%s**\n%s\n| Domain | Result |\n| --- | --- |\n", escape(run.RunID), escape(run.Acceptance), escape(run.State), sourceLine); err != nil {
		return err
	}
	for _, domain := range []string{"integrity", "readiness", "workflow", "recovery"} {
		status := run.Domains[domain]
		if status == "" {
			status = "not_tested"
		}
		if _, err := fmt.Fprintf(w, "| %s | %s |\n", domain, escape(status)); err != nil {
			return err
		}
	}
	var observations strings.Builder
	for _, check := range run.Checks {
		o := check.Observations
		if o == nil {
			continue
		}
		fmt.Fprintf(&observations, "\nApplication-reported numeric observations: **%s** (%s)\n\nDeclared profile: %s. Test: %s; assertions: %s. Samples: %d.\n\nSampling: %s\n\nNondeterminism: %s\n\nLimitations: %s\n\n| Metric | Kind | Assertion | Min | Max | Unit |\n| --- | --- | --- | --- | --- | --- |\n", escape(check.ID), escape(check.Status), escape(o.Contract.Profile), escape(o.Contract.TestRevision), escape(o.Contract.AssertionRevision), o.Contract.SampleCount, escape(fmt.Sprint(o.Contract.Sampling)), escape(o.Contract.Nondeterminism), escape(o.Contract.Limitations))
		for _, metric := range o.Contract.Metrics {
			fmt.Fprintf(&observations, "| %s | %s | %s | %s | %s | %s |\n", escape(metric.Name), escape(metric.Kind), escape(metric.Assertion), observationNumber(metric.Min), observationNumber(metric.Max), escape(metric.Unit))
		}
		if o.Report == nil {
			observations.WriteString("\nNo valid numeric document captured.\n")
			continue
		}
		fmt.Fprintf(&observations, "\nApplication-observed runtime: %s; device: %s; mode: %s; warm/cold: %s; concurrency: %d.\n\n| Sample | Metric | Value | Unit | Against bounds |\n| --- | --- | --- | --- | --- |\n", escape(o.Report.Runtime), escape(o.Report.Device), escape(o.Report.Mode), escape(o.Report.WarmCold), o.Report.Concurrency)
		for _, sample := range o.Report.Samples {
			for _, metric := range sample.Metrics {
				fmt.Fprintf(&observations, "| %d | %s | %s | %s | %s |\n", sample.Index, escape(metric.Name), observationNumber(metric.Value), escape(metric.Unit), observationAssessment(o.Contract, metric))
			}
		}
	}
	if _, err := io.WriteString(w, observations.String()); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, "\nCoverage applies only to this recorded release, profile and required workflows. Full diagnostics remain local.")
	return err
}

func observationAssessment(contract spec.ObservationContract, value spec.MetricValue) string {
	for _, bound := range contract.Metrics {
		if bound.Name != value.Name || bound.Unit != value.Unit || bound.Min == nil || bound.Max == nil || value.Value == nil || *bound.Min > *bound.Max {
			continue
		}
		if *value.Value < *bound.Min || *value.Value > *bound.Max {
			return "outside bounds"
		}
		return "within bounds"
	}
	return "not assessed"
}

func observationNumber(value *int64) string {
	if value == nil {
		return "not recorded"
	}
	return strconv.FormatInt(*value, 10)
}

const observationTemplate = `{{define "observations"}}
<p class="muted">Values and device metadata are application-reported, not independent GPU memory instrumentation.</p>
<dl><dt>Declared profile</dt><dd>{{.Contract.Profile}}</dd><dt>Test revision</dt><dd>{{.Contract.TestRevision}}</dd><dt>Assertion revision</dt><dd>{{.Contract.AssertionRevision}}</dd><dt>Declared samples</dt><dd>{{.Contract.SampleCount}}</dd><dt>Sampling</dt><dd>{{range $key, $value := .Contract.Sampling}}{{$key}}={{$value}}; {{end}}</dd><dt>Nondeterminism</dt><dd>{{.Contract.Nondeterminism}}</dd><dt>Limitations</dt><dd>{{.Contract.Limitations}}</dd></dl>
<table><caption>Declared inclusive bounds</caption><thead><tr><th scope="col">Metric</th><th scope="col">Kind</th><th scope="col">Assertion</th><th scope="col">Min</th><th scope="col">Max</th><th scope="col">Unit</th></tr></thead><tbody>{{range .Contract.Metrics}}<tr><th scope="row">{{.Name}}</th><td data-label="Kind">{{.Kind}}</td><td data-label="Assertion">{{.Assertion}}</td><td data-label="Min">{{number .Min}}</td><td data-label="Max">{{number .Max}}</td><td data-label="Unit">{{.Unit}}</td></tr>{{end}}</tbody></table>
{{$contract := .Contract}}{{with .Report}}<dl><dt>Runtime</dt><dd>{{.Runtime}}</dd><dt>Device</dt><dd>{{.Device}}</dd><dt>Mode</dt><dd>{{.Mode}}</dd><dt>Warm/cold</dt><dd>{{.WarmCold}}</dd><dt>Concurrency</dt><dd>{{.Concurrency}}</dd></dl>
<table><caption>Every ordered sample</caption><thead><tr><th scope="col">Sample</th><th scope="col">Metric</th><th scope="col">Value</th><th scope="col">Unit</th><th scope="col">Against bounds</th></tr></thead><tbody>{{range $sample := .Samples}}{{range .Metrics}}{{$assessment := assessment $contract .}}<tr><th scope="row" data-label="Sample">{{$sample.Index}}</th><td data-label="Metric">{{.Name}}</td><td data-label="Value">{{number .Value}}</td><td data-label="Unit">{{.Unit}}</td><td data-label="Against bounds"{{if eq $assessment "outside bounds"}} class="exception"{{end}}>{{$assessment}}</td></tr>{{end}}{{end}}</tbody></table>{{else}}<p>No valid numeric document captured.</p>{{end}}
<dl><dt>Original Job</dt><dd>{{.Source.JobName}} / {{.Source.JobUID}}</dd><dt>Original Pod</dt><dd>{{.Source.PodName}} / {{.Source.PodUID}}</dd><dt>Job recipe</dt><dd>{{.Source.RecipeDigest}}</dd><dt>Output digest</dt><dd>{{.Source.OutputDigest}}</dd></dl>
{{end}}`

const reportTemplate = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Cinderlock run {{.Run.RunID}}</title><style>body{margin:0;background:#101a1c;color:#edf4f1;font:1rem/1.6 system-ui,sans-serif}main,header{max-width:76rem;padding:1.5rem;margin:auto}h1{font-size:2.5rem;line-height:1.15}h2{margin-top:2rem}a{color:#8ff0cc}a:focus-visible,summary:focus-visible{outline:3px solid white;outline-offset:4px}.skip{position:absolute;left:-999px}.skip:focus{left:1rem;top:.5rem;background:#101a1c}table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #55736b;padding:.8rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}caption{text-align:left;font-weight:bold;padding:.5rem 0}dl{display:grid;grid-template-columns:minmax(8rem,1fr) 3fr;gap:.5rem}dt{font-weight:bold}dd{margin:0;overflow-wrap:anywhere}.note{border-left:4px solid #8ff0cc;padding:1rem}.muted{color:#b6c9c3}.exception{color:#ffd1bd;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere}summary{padding:.5rem;cursor:pointer}@media(max-width:40rem){caption{display:block}dl{display:block}dd{margin-bottom:1rem}table,tbody,tr,th,td{display:block}thead{position:absolute;left:-9999px}th[data-label="Sample"]{border-top:2px solid #8ff0cc;background:#172a2a}td[data-label]:before,th[data-label]:before{content:attr(data-label) ': ';font-weight:bold}}</style></head><body><a class="skip" href="#main">Skip to results</a><header><p>CINDERLOCK / LOCAL RELEASE EVIDENCE</p><h1>{{.Run.Acceptance}}</h1><p>Run state: <strong>{{.Run.State}}</strong></p><p class="note">{{.Next}}</p></header><main id="main"><h2>Release and target</h2><dl><dt>Application</dt><dd>{{.Run.Metadata.Application}} {{.Run.Metadata.Version}}</dd><dt>Run</dt><dd>{{.Run.RunID}}</dd>{{if .Run.SourceRun}}<dt>Source run</dt><dd>{{.Run.SourceRun}}</dd>{{end}}<dt>Site</dt><dd>{{.Run.SiteID}}</dd><dt>Target</dt><dd>{{.Run.TargetID}}</dd><dt>Bundle</dt><dd>{{.Run.BundleDigest}}</dd><dt>Plan</dt><dd>{{.Run.PlanDigest}}</dd><dt>Started</dt><dd>{{.Run.StartedAt}}</dd><dt>Finished</dt><dd>{{if .Run.FinishedAt}}{{.Run.FinishedAt}}{{else}}Not recorded{{end}}</dd></dl><h2>Coverage and acceptance</h2><p class="muted">Resource readiness, required workflows and recovery are separate. A passing upgrade does not establish production-data recovery or universal offline readiness.</p><table><caption>Four result domains</caption><thead><tr><th scope="col">Domain</th><th scope="col">Result</th></tr></thead><tbody>{{range .Domains}}<tr><th scope="row">{{.Name}}</th><td data-label="Result">{{.Status}}</td></tr>{{end}}</tbody></table><dl><dt>Recovery coverage</dt><dd>{{if .Run.RecoveryCoverage}}{{.Run.RecoveryCoverage}}{{else}}Not tested; scope not supplied{{end}}</dd><dt>Offline coverage</dt><dd>{{if .Run.OfflineCoverage}}{{.Run.OfflineCoverage}}{{else}}Not tested; scope not supplied{{end}}</dd></dl><h2>Operation timeline</h2><table><caption>Attempts and observed outcomes</caption><thead><tr><th scope="col">Step</th><th scope="col">Attempt</th><th scope="col">Status</th><th scope="col">Observation</th></tr></thead><tbody>{{range .Run.Steps}}<tr><th scope="row">{{.ID}}</th><td data-label="Attempt">{{.Attempt}}</td><td data-label="Status">{{.Status}}</td><td data-label="Observation">{{.Error}}{{if .Evidence}}<details><summary>Local evidence reference</summary><pre>{{.Evidence}}</pre></details>{{end}}</td></tr>{{else}}<tr><td colspan="4">No step observations recorded.</td></tr>{{end}}</tbody></table><h2>Required workflows</h2><table><caption>Recorded test contracts and outcomes</caption><thead><tr><th scope="col">Check</th><th scope="col">Required</th><th scope="col">Domain</th><th scope="col">Result</th><th scope="col">Reason</th></tr></thead><tbody>{{range .Run.Checks}}<tr><th scope="row">{{.ID}}</th><td data-label="Required">{{.Required}}</td><td data-label="Domain">{{.Domain}}</td><td data-label="Result">{{.Status}}</td><td data-label="Reason">{{.Reason}}{{if .Observations}} <a href="#observations-{{.ID}}">Numeric observations</a>{{end}}</td></tr>{{else}}<tr><td colspan="5">No checks recorded; application acceptance cannot be inferred.</td></tr>{{end}}</tbody></table>{{range .Run.Checks}}{{if .Observations}}<section id="observations-{{.ID}}"><h2>Application observations: {{.ID}}</h2><p>Recorded check result: {{.Status}}</p><details><summary>Application-reported numeric observations</summary>{{template "observations" .Observations}}</details></section>{{end}}{{end}}<h2>Diagnostics</h2>{{if .Run.Error}}<p>{{.Run.Error}}</p>{{end}}{{range .Run.Findings}}<article><h3>{{.Code}}</h3><p>{{.Severity}}: {{.Message}}</p>{{if .Evidence}}<details><summary>Local evidence reference</summary><pre>{{.Evidence}}</pre></details>{{end}}</article>{{else}}<p>No additional findings recorded.</p>{{end}}<h2>Evidence handling</h2><p>This report can contain sensitive local observations. Support exports are separate allowlisted snapshots reviewed under customer policy. This report makes no independent certification claim.</p></main></body></html>`
