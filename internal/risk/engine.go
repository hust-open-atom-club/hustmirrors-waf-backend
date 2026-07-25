package risk

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

type Engine struct {
	chains ChainMap
	mu     sync.RWMutex
}

var ErrNoChains = errors.New("risk: no chains configured")

func NewEngine(chains ChainMap) (*Engine, error) {
	if len(chains) == 0 {
		return nil, ErrNoChains
	}
	return &Engine{chains: chains}, nil
}

// evalState carries the accumulator state that flows through recursive
// evalChain calls: the trace for diagnostics, the marks accumulated by
// MARK targets, and the visited counter for cycle detection.
type evalState struct {
	trace   *[]TraceStep
	marks   *[]string
	visited map[string]int
}

// Evaluate walks the "INPUT" chain and returns the resulting Decision
// along with a per-step trace. When ctx.Counters is nil, counter-based
// matchers evaluate to false.
func (e *Engine) Evaluate(_ context.Context, ctx *RequestContext) (Result, error) {
	if ctx == nil {
		ctx = &RequestContext{}
	}
	if ctx.Counters == nil {
		ctx.Counters = NoopCounterResolver
	}
	r := Result{Trace: []TraceStep{}}
	marks := []string{}
	st := evalState{trace: &r.Trace, marks: &marks, visited: make(map[string]int, len(e.chains))}
	d, err := e.evalChain("INPUT", ctx, st)
	if err != nil {
		return r, err
	}
	d.Marks = marks
	r.Decision = d
	return r, nil
}

// EvaluateWithEntry is like Evaluate but lets the caller pick the entry
// chain name.
func (e *Engine) EvaluateWithEntry(_ context.Context, ctx *RequestContext, entry string) (Result, error) {
	if entry == "" {
		entry = "INPUT"
	}
	if ctx == nil {
		ctx = &RequestContext{}
	}
	if ctx.Counters == nil {
		ctx.Counters = NoopCounterResolver
	}
	r := Result{Trace: []TraceStep{}}
	marks := []string{}
	st := evalState{trace: &r.Trace, marks: &marks, visited: make(map[string]int, len(e.chains))}
	d, err := e.evalChain(entry, ctx, st)
	if err != nil {
		return r, err
	}
	d.Marks = marks
	r.Decision = d
	return r, nil
}

// lookupChain returns the chain with the given name, doing a
// case-insensitive comparison because viper lowercases YAML keys.
func (e *Engine) lookupChain(name string) (*Chain, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if c, ok := e.chains[name]; ok {
		return c, true
	}
	upper := strings.ToUpper(name)
	for k, v := range e.chains {
		if strings.ToUpper(k) == upper {
			return v, true
		}
	}
	return nil, false
}

func (e *Engine) hasChain(name string) bool {
	_, ok := e.lookupChain(name)
	return ok
}

// evalChain walks a single chain. visited prevents infinite recursion via
// JUMP chains (defensive; config validation should already reject cycles).
func (e *Engine) evalChain(name string, ctx *RequestContext, st evalState) (Decision, error) {
	chain, ok := e.lookupChain(name)
	if !ok {
		return Decision{}, fmt.Errorf("risk: chain %q not found", name)
	}
	st.visited[strings.ToUpper(name)]++
	if st.visited[strings.ToUpper(name)] > 8 {
		return Decision{Target: TargetREJECT, StatusCode: 500, Reason: "chain_depth_exceeded", Chain: name}, nil
	}

	for i := range chain.Rules {
		rule := chain.Rules[i]
		matched := rule.Match.Match(ctx)
		step := TraceStep{
			Chain:   name,
			Rule:    rule.Name,
			Matched: matched,
		}
		if matched {
			step.Target = rule.Target
			if rule.Target == TargetJUMP {
				step.JumpTo = rule.Chain
			}
			*st.trace = append(*st.trace, step)
			switch rule.Target {
			case TargetACCEPT, TargetREJECT, TargetRATELIMIT, TargetTOOMANY, TargetREQUIREPOW:
				dec := decisionFromRule(name, rule)
				dec.Marks = *st.marks
				return dec, nil
			case TargetJUMP:
				dec, err := e.evalChain(rule.Chain, ctx, st)
				if err != nil {
					return dec, err
				}
				if isTerminal(dec.Target) {
					if dec.Reason == "" {
						dec.Reason = rule.Reason
					}
					return dec, nil
				}
			case TargetRETURN:
				return e.applyPolicy(name, chain, st)
			case TargetLOG:
				// Non-terminal: continue to next rule.
			case TargetMARK:
				if rule.Mark != "" {
					*st.marks = append(*st.marks, rule.Mark)
				}
			}
		} else {
			*st.trace = append(*st.trace, step)
		}
	}
	return e.applyPolicy(name, chain, st)
}

func (e *Engine) applyPolicy(chainName string, chain *Chain, st evalState) (Decision, error) {
	return Decision{
		Target:     chain.Policy.Target,
		StatusCode: chain.Policy.Status,
		LimitRate:  chain.Policy.LimitRate,
		Reason:     chain.Policy.Reason,
		Chain:      chainName,
		RuleName:   "policy",
		Marks:      *st.marks,
	}, nil
}

func decisionFromRule(chainName string, rule Rule) Decision {
	status := rule.Status
	if status == 0 {
		status = defaultStatusCodeFor(rule.Target)
	}
	return Decision{
		Target:    rule.Target,
		StatusCode: status,
		LimitRate: rule.LimitRate,
		Reason:    rule.Reason,
		Chain:     chainName,
		RuleName:  rule.Name,
	}
}
