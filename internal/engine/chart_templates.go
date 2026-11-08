package engine

import (
	"text/template/parse"

	"github.com/cenab/cinderlock/internal/spec"
)

func inspectChartTemplate(name, source string) error {
	trees := map[string]*parse.Tree{}
	tree := parse.New(name)
	// Helm owns function resolution; this pass inspects syntax without executing it.
	tree.Mode = parse.SkipFuncCheck
	if _, err := tree.Parse(source, "", "", trees); err != nil {
		return spec.Err(10, "chart template cannot be inspected in the supported profile")
	}
	var pending []parse.Node
	for _, tree := range trees {
		pending = append(pending, tree.Root)
	}
	for count := 0; len(pending) > 0; count++ {
		if count >= 10000 {
			return spec.Err(10, "chart template exceeds supported syntax complexity")
		}
		node := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		switch n := node.(type) {
		case *parse.ListNode:
			if n != nil {
				pending = append(pending, n.Nodes...)
			}
		case *parse.ActionNode:
			pending = append(pending, n.Pipe)
		case *parse.PipeNode:
			if n != nil {
				for _, command := range n.Cmds {
					pending = append(pending, command)
				}
			}
		case *parse.CommandNode:
			pending = append(pending, n.Args...)
		case *parse.IfNode:
			pending = append(pending, n.Pipe, n.List, n.ElseList)
		case *parse.RangeNode:
			pending = append(pending, n.Pipe, n.List, n.ElseList)
		case *parse.WithNode:
			pending = append(pending, n.Pipe, n.List, n.ElseList)
		case *parse.TemplateNode:
			pending = append(pending, n.Pipe)
		case *parse.ChainNode:
			pending = append(pending, n.Node)
		case *parse.IdentifierNode:
			switch n.Ident {
			case "tpl", "call", "lookup", "getHostByName", "env", "expandenv",
				"now", "ago", "date", "date_in_zone", "dateInZone", "date_modify", "dateModify",
				"htmlDate", "htmlDateInZone", "durationRound",
				"toDate", "mustToDate",
				"randAlphaNum", "randAlpha", "randAscii", "randNumeric", "randBytes", "randInt", "shuffle", "uuidv4",
				"bcrypt", "htpasswd", "genPrivateKey", "genCA", "genCAWithKey", "genSelfSignedCert", "genSelfSignedCertWithKey",
				"genSignedCert", "genSignedCertWithKey", "encryptAES":
				return spec.Err(10, "chart uses unsupported dynamic, environment-dependent, or nondeterministic template function")
			}
		}
	}
	return nil
}
