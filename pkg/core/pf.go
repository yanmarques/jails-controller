package controller

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
)

const (
	PF_INGRESS = "in"
	PF_EGRESS  = "out"
)

type Pf struct {
	Config           Config
	NatAnchorFile    string
	FilterAnchorFile string
	LastHash         []byte
}

type PfPolicy struct {
	Action    string
	Direction string
	Interface string
	Protocol  []string
	From      []string
	FromPort  []int
	To        []string
	ToPort    []int
	Flags     string
	State     string
}

func PfMacro[I int | string](items []I, quote bool) string {
	var buffer strings.Builder

	if quote {
		buffer.WriteString("\"{ ")
	} else {
		buffer.WriteString("{ ")
	}

	for i, item := range items {
		fmt.Fprintf(&buffer, "%v", item)
		if i != len(items)-1 {
			buffer.WriteString(",")
		}
	}

	if quote {
		buffer.WriteString(" }\"")
	} else {
		buffer.WriteString(" }")
	}

	return buffer.String()
}

func NewPf(config Config, natAnchorFile, filterAnchorFile string) *Pf {
	return &Pf{
		Config:           config,
		NatAnchorFile:    natAnchorFile,
		FilterAnchorFile: filterAnchorFile,
		LastHash:         []byte{},
	}
}

func (p *Pf) Init() error {
	subnets := []string{}

	for _, subnet := range p.Config.Subnets {
		subnets = append(subnets, subnet.Cidr)
	}

	natRules := []string{
		"ext_if = " + p.Config.ExtIf,
		"subnets = " + PfMacro(subnets, true),
		"nat on $ext_if from $subnets to any -> ($ext_if)",
	}

	natContents := []byte(strings.Join(natRules, "\n"))

	err := os.WriteFile(p.NatAnchorFile, natContents, os.FileMode(0640))

	_, err = os.Stat(p.FilterAnchorFile)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.WriteFile(p.FilterAnchorFile, []byte(""), os.FileMode(0640))
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	if err == nil {
		_, _, err = RunCmd(&CmdOptions{
			Path: "/usr/sbin/service",
			Args: []string{"pf", "reload"},
		})

		return err
	}

	return err
}

func (p *Pf) SetRules(policies []*PfPolicy) error {
	log.Printf("pf sync filters")

	rules := []string{"ext_if = " + p.Config.ExtIf}

	var rule strings.Builder

	for _, policy := range policies {
		rule.WriteString(policy.Action)
		rule.WriteString(" ")
		rule.WriteString(policy.Direction)
		rule.WriteString(" ")
		rule.WriteString("on ")
		rule.WriteString(policy.Interface)
		rule.WriteString(" inet ")

		if len(policy.Protocol) > 0 {
			rule.WriteString("proto ")
			rule.WriteString(PfMacro(policy.Protocol, false))
			rule.WriteString(" ")
		}

		if len(policy.From) > 0 {
			rule.WriteString("from ")
			rule.WriteString(PfMacro(policy.From, false))
			rule.WriteString(" ")
		} else {
			rule.WriteString("from any ")
		}

		if len(policy.FromPort) > 0 {
			rule.WriteString("port ")
			rule.WriteString(PfMacro(policy.FromPort, false))
			rule.WriteString(" ")
		}

		if len(policy.To) > 0 {
			rule.WriteString("to ")
			rule.WriteString(PfMacro(policy.To, false))
			rule.WriteString(" ")
		} else {
			rule.WriteString("to any ")
		}

		if len(policy.ToPort) > 0 {
			rule.WriteString("port ")
			rule.WriteString(PfMacro(policy.ToPort, false))
			rule.WriteString(" ")
		}

		if policy.Flags != "" {
			rule.WriteString(policy.Flags)
		}

		if policy.State != "" {
			rule.WriteString(policy.State)
		}

		rules = append(rules, rule.String())

		rule.Reset()
	}

	filterContents := []byte(strings.Join(rules, "\n"))

	hash := sha256.Sum256(filterContents)

	if slices.Compare(hash[:], p.LastHash) == 0 {
		return nil
	}

	p.LastHash = hash[:]

	err := os.WriteFile(p.FilterAnchorFile, filterContents, os.FileMode(0640))

	if err == nil {
		_, _, err = RunCmd(&CmdOptions{
			Path: "/usr/sbin/service",
			Args: []string{"pf", "reload"},
		})

		return err
	}

	return err
}
