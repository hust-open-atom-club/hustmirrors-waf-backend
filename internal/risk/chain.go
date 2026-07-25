package risk

type Rule struct {
	Name      string
	Match     Matcher
	Target    string
	Chain     string // for JUMP
	Status    int    // 0 means use defaultStatusCodeFor
	LimitRate string
	Reason    string
	Mark      string
}

type Chain struct {
	Name   string
	Rules  []Rule
	Policy Policy
}

type Policy struct {
	Target    string
	Status    int
	LimitRate string
	Reason    string
}

type ChainMap map[string]*Chain
