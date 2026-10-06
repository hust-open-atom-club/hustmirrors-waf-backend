// Command garmr is the local management CLI for the Garmr PoW gateway.
//
//	garmr config show|edit|validate|diff|history|rollback  — configuration workflow
//	garmr rule list|preview                               — risk-chain inspection
//
// Configuration commands operate on the config file directly (the service
// does not need to be running); rule commands build the risk engine from
// the same file in-process.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/configctl"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/matcher"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
)

const usage = `garmr - local management for the Garmr PoW gateway

Usage:
  garmr [global flags] <command> [args]

Global flags:
  -config path   configuration file (default /etc/mirrors-waf/config.yaml)

Commands:
  config show              print the active configuration (secrets redacted)
  config show <revision>   print a historical revision (secrets redacted)
  config edit              edit in $EDITOR: validate -> diff -> confirm -> apply
  config validate <file>   validate a candidate YAML file
  config diff <file>       diff a candidate file against the active config
  config history           list revision history
  config rollback <rev>    restore a historical revision (with diff preview)
  rule list                list risk chains and rules
  rule preview             evaluate a hypothetical request through the chains

Run "garmr <command>" without further args for command-specific flags.
`

func main() {
	global := flag.NewFlagSet("garmr", flag.ContinueOnError)
	configPath := global.String("config", "/etc/mirrors-waf/config.yaml", "configuration file")
	if err := global.Parse(os.Args[1:]); err != nil {
		exitf("%v", err)
	}
	args := global.Args()
	if len(args) == 0 {
		fmt.Print(usage)
		os.Exit(2)
	}
	switch args[0] {
	case "config":
		runConfig(*configPath, args[1:])
	case "rule":
		runRule(*configPath, args[1:])
	default:
		exitf("unknown command %q\n\n%s", args[0], usage)
	}
}

func exitf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "garmr: "+format+"\n", args...)
	os.Exit(1)
}

/* ---------------------------- config ---------------------------- */

func runConfig(path string, args []string) {
	cmd := "show"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	switch cmd {
	case "show":
		configShow(path, args)
	case "edit":
		configEdit(path)
	case "validate":
		if len(args) != 1 {
			exitf("usage: garmr config validate <file>")
		}
		configValidate(args[0])
	case "diff":
		if len(args) != 1 {
			exitf("usage: garmr config diff <file>")
		}
		configDiff(path, args[0])
	case "history":
		configHistory(path)
	case "rollback":
		if len(args) != 1 {
			exitf("usage: garmr config rollback <revision>")
		}
		rev, err := strconv.ParseUint(args[0], 10, 64)
		if err != nil {
			exitf("invalid revision %q", args[0])
		}
		configRollback(path, rev)
	default:
		exitf("unknown config subcommand %q", cmd)
	}
}

func openManager(path string) *configctl.Manager {
	m, err := configctl.Open(path)
	if err != nil {
		exitf("%v", err)
	}
	return m
}

func configShow(path string, args []string) {
	m := openManager(path)
	if len(args) == 0 {
		_, redacted, err := m.Redacted()
		if err != nil {
			exitf("%v", err)
		}
		fmt.Print(redacted)
		return
	}
	rev, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil {
		exitf("invalid revision %q", args[0])
	}
	item, err := m.HistoryGet(rev)
	if err != nil {
		exitf("%v", err)
	}
	fmt.Print(configctl.RedactYAML(item.Raw))
}

func configEdit(path string) {
	m := openManager(path)
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	_, redacted, err := m.Redacted()
	if err != nil {
		exitf("%v", err)
	}
	tmp, err := os.CreateTemp("", "garmr-config-*.yaml")
	if err != nil {
		exitf("temp file: %v", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.WriteString(redacted); err != nil {
		exitf("temp file: %v", err)
	}
	tmp.Close()

	for {
		edit := exec.Command(editor, name)
		edit.Stdin, edit.Stdout, edit.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := edit.Run(); err != nil {
			exitf("editor: %v", err)
		}
		edited, err := os.ReadFile(name)
		if err != nil {
			exitf("read edit: %v", err)
		}
		if string(edited) == redacted {
			fmt.Println("未修改，退出。")
			return
		}
		problems, err := configctl.ValidateYAML(edited)
		if err != nil {
			fmt.Printf("校验失败：%v\n重新编辑？[Y/n] ", err)
			if confirm(true) {
				continue
			}
			return
		}
		if len(problems) > 0 {
			fmt.Println("校验未通过：")
			for _, problem := range problems {
				fmt.Println("  -", problem)
			}
			fmt.Print("重新编辑？[Y/n] ")
			if confirm(true) {
				continue
			}
			return
		}
		candidate, err := m.MergeSecrets(string(edited))
		if err != nil {
			fmt.Printf("敏感值合并失败：%v\n重新编辑？[Y/n] ", err)
			if confirm(true) {
				continue
			}
			return
		}
		plan, err := m.Plan(candidate, "apply")
		if err != nil {
			exitf("%v", err)
		}
		if len(plan.Changes) == 0 {
			fmt.Println("与当前配置无差异，退出。")
			return
		}
		printPlan(plan)
		if !applyPrompt(plan) {
			fmt.Println("已放弃。")
			return
		}
		reason := promptRequired("变更原因: ")
		result, err := m.Apply(candidate, plan, reason, currentUser(), "apply", 0)
		if err != nil {
			exitf("apply: %v", err)
		}
		fmt.Printf("已写入 revision %d（重启服务后生效）。\n", result.Revision)
		return
	}
}

func configValidate(file string) {
	raw, err := os.ReadFile(file)
	if err != nil {
		exitf("%v", err)
	}
	problems, err := configctl.ValidateYAML(raw)
	if err != nil {
		exitf("%v", err)
	}
	if len(problems) > 0 {
		fmt.Println("校验未通过：")
		for _, problem := range problems {
			fmt.Println("  -", problem)
		}
		os.Exit(1)
	}
	fmt.Println("OK")
}

func configDiff(path, file string) {
	m := openManager(path)
	raw, err := os.ReadFile(file)
	if err != nil {
		exitf("%v", err)
	}
	candidate, err := m.MergeSecrets(string(raw))
	if err != nil {
		exitf("%v（diff 命令的输入应保留 $%s 占位符）", err, "{SECRET:KEEP}")
	}
	plan, err := m.Plan(candidate, "apply")
	if err != nil {
		exitf("%v", err)
	}
	printPlan(plan)
}

func configHistory(path string) {
	m := openManager(path)
	items, err := m.History(50)
	if err != nil {
		exitf("%v", err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "REVISION\tPARENT\tACTION\tCHANGED\tDANGER\tACTOR\tWHEN\tREASON")
	for _, item := range items {
		reason := item.Reason
		if item.RollbackTarget > 0 {
			reason = fmt.Sprintf("rollback -> #%d %s", item.RollbackTarget, reason)
		}
		fmt.Fprintf(w, "#%d\t#%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			item.Revision, dash(item.ParentRevision), item.Action, item.Changed,
			item.Danger, dashEmpty(item.Actor), item.CreatedAt.Format("2006-01-02 15:04"), reason)
	}
	w.Flush()
}

func configRollback(path string, rev uint64) {
	m := openManager(path)
	plan, target, err := m.PlanRollback(rev)
	if err != nil {
		exitf("%v", err)
	}
	if len(plan.Changes) == 0 {
		fmt.Printf("revision #%d 与当前配置一致，无需回滚。\n", rev)
		return
	}
	fmt.Printf("回滚到 revision #%d（%s，%d 项变更）：\n", rev, target.Meta.CreatedAt.Format("2006-01-02 15:04"), len(plan.Changes))
	printPlan(plan)
	if !applyPrompt(plan) {
		fmt.Println("已放弃。")
		return
	}
	reason := promptRequired("回滚原因: ")
	result, err := m.Apply(target.Raw, plan, reason, currentUser(), "rollback", rev)
	if err != nil {
		exitf("rollback: %v", err)
	}
	fmt.Printf("已回滚到 #%d，生成 revision %d（重启服务后生效）。\n", rev, result.Revision)
}

/* ---------------------------- rule ---------------------------- */

func runRule(configDefault string, args []string) {
	cmd := "list"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	switch cmd {
	case "list":
		ruleList(configDefault)
	case "preview":
		rulePreview(configDefault, args)
	default:
		exitf("unknown rule subcommand %q", cmd)
	}
}

func loadConfig(path string) *config.Config {
	cfg, err := config.Load(path)
	if err != nil {
		exitf("load config: %v", err)
	}
	return cfg
}

func ruleList(path string) {
	cfg := loadConfig(path)
	names := make([]string, 0, len(cfg.RiskControl.Chains))
	for name := range cfg.RiskControl.Chains {
		names = append(names, name)
	}
	sort.Strings(names)
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	for _, name := range names {
		chain := cfg.RiskControl.Chains[name]
		fmt.Fprintf(w, "chain %s\tpolicy: %s\n", name, chain.Policy.Target)
		for i, rule := range chain.Rules {
			target := rule.Target
			if rule.Chain != "" {
				target = target + " -> " + rule.Chain
			}
			fmt.Fprintf(w, "  %d. %s\t%s\t%s\n", i+1, rule.Name, target, dashEmpty(rule.Reason))
		}
		fmt.Fprintln(w)
	}
	w.Flush()
}

func rulePreview(configDefault string, args []string) {
	fs := flag.NewFlagSet("rule preview", flag.ContinueOnError)
	path := fs.String("path", "/ubuntu.iso", "request path")
	method := fs.String("method", "GET", "request method")
	ip := fs.String("ip", "192.0.2.1", "client IP")
	powStatus := fs.String("pow", "missing", "pow status: missing|valid|invalid|expired|used_up|mode_disabled|unverifiable")
	powMode := fs.String("pow-mode", "", "pow mode (generic|ip_bound)")
	if err := fs.Parse(args); err != nil {
		exitf("%v", err)
	}
	cfg := loadConfig(configDefault)
	engine, err := risk.FromConfig(cfg.RiskControl)
	if err != nil {
		exitf("build engine: %v", err)
	}
	m := buildMatcher(cfg)
	rctx := &risk.RequestContext{
		Path: *path, Method: *method, IP: *ip, PowStatus: *powStatus, PowMode: *powMode,
		IsProtected: m.ShouldProtect(*path), IsRangeRequest: false,
	}
	result, err := engine.Evaluate(context.Background(), rctx)
	if err != nil {
		exitf("evaluate: %v", err)
	}
	fmt.Printf("decision: %s (HTTP %d)  chain=%s rule=%s\n", result.Decision.Target, result.Decision.StatusCode, result.Decision.Chain, dashEmpty(result.Decision.RuleName))
	fmt.Printf("reason:   %s\n", result.Decision.Reason)
	if result.Decision.LimitRate != "" && result.Decision.LimitRate != "0" {
		fmt.Printf("limit:    %s\n", result.Decision.LimitRate)
	}
	if len(result.Trace) > 0 {
		fmt.Println("trace:")
		for _, step := range result.Trace {
			mark := " "
			if step.Matched {
				mark = "v"
			}
			fmt.Printf("  [%s] %s: %s\n", mark, step.Chain, step.Rule)
		}
	}
}

// buildMatcher assembles the protection matcher the same way the service
// does, so rule preview sees the same protected-path classification.
func buildMatcher(cfg *config.Config) *matcher.Composite {
	ext := matcher.NewExtensionMatcher(cfg.Protection.ProtectedExtensions)
	protected := matcher.Matcher(ext)
	if len(cfg.Protection.ProtectedPaths) > 0 {
		if regex, err := matcher.NewRegexMatcher(cfg.Protection.ProtectedPaths); err == nil {
			protected = regex
		}
	}
	var excluded matcher.Matcher
	if len(cfg.Protection.ExcludedPaths) > 0 {
		if regex, err := matcher.NewRegexMatcher(cfg.Protection.ExcludedPaths); err == nil {
			excluded = regex
		}
	}
	return matcher.NewComposite(protected, excluded)
}

/* ---------------------------- shared helpers ---------------------------- */

func printPlan(plan configctl.Plan) {
	fmt.Printf("基于 revision #%d，%d 项变更，危险级别 %s\n", plan.BaseRevision, len(plan.Changes), plan.Danger)
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	for _, change := range plan.Changes {
		fmt.Fprintf(w, "  %s\t%s\t%s -> %s\n", change.Path, change.Kind, formatValue(change.Before, change.Sensitive), formatValue(change.After, change.Sensitive))
	}
	w.Flush()
}

func formatValue(value interface{}, sensitive bool) string {
	if sensitive {
		return "(redacted)"
	}
	if value == nil {
		return "-"
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprintf("%v", value)
}

func applyPrompt(plan configctl.Plan) bool {
	if plan.ConfirmationRequired() {
		fmt.Printf("确认短语: %s\n", plan.Phrase)
		fmt.Print("输入确认短语: ")
		phrase := readLine()
		if phrase != plan.Phrase {
			fmt.Println("短语不匹配。")
			return false
		}
	}
	fmt.Print("应用以上变更？[y/N] ")
	return confirm(false)
}

func promptRequired(label string) string {
	for {
		fmt.Print(label)
		value := strings.TrimSpace(readLine())
		if value != "" {
			return value
		}
	}
}

func readLine() string {
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func confirm(defaultYes bool) bool {
	answer := strings.ToLower(readLine())
	if answer == "" {
		return defaultYes
	}
	return answer == "y" || answer == "yes"
}

func currentUser() string {
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	if user == "" {
		return os.Getenv("LOGNAME")
	}
	return user
}

func dash(v uint64) string {
	if v == 0 {
		return "-"
	}
	return strconv.FormatUint(v, 10)
}

func dashEmpty(v string) string {
	if v == "" {
		return "-"
	}
	return v
}
