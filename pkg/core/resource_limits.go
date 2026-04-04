package controller

import (
	"bytes"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

var RCTL_UNIT_SUFFIXES_LOWER = []byte{
	'B',
	'K',
	'M',
	'G',
	'T',
	'P',
}

var RCTL_UNIT_SUFFIXES_UPPER = []byte{
	'B',
	'K',
	'M',
	'G',
	'T',
	'P',
}

type JailResourceManager struct {
	Limits map[string]map[string]ResourceLimit
}

type ResourceLimit struct {
	Resource string
	Action   string
	Amount   string
}

func NewJailResourceManager() *JailResourceManager {
	return &JailResourceManager{
		Limits: map[string]map[string]ResourceLimit{},
	}
}

func (r *JailResourceManager) set(jail, rule string, rlimit ResourceLimit) {
	_, ok := r.Limits[jail]
	if !ok {
		r.Limits[jail] = map[string]ResourceLimit{}
	}

	r.Limits[jail][rule] = rlimit
}

func (r *ResourceLimit) Rule(jail string) string {
	amount := r.Amount
	hasUnitSuffix := slices.Contains(RCTL_UNIT_SUFFIXES_LOWER, amount[len(amount)-1])

	if hasUnitSuffix {
		suffix := byte(unicode.ToUpper(rune(amount[len(amount)-1])))
		byteStr := []byte(amount)
		byteStr[len(amount)-1] = suffix
		amount = string(byteStr)
	}

	return "jail:" + jail + ":" + r.Resource + ":" + r.Action + "=" + amount
}

func (r *ResourceLimit) Validate() error {
	if r.Resource == "" || strings.TrimSpace(r.Resource) == "" {
		return fmt.Errorf("resource can not be empty")
	}

	if r.Action == "" || strings.TrimSpace(r.Action) == "" {
		return fmt.Errorf("resource action can not be empty")
	}

	if r.Amount == "" || strings.TrimSpace(r.Amount) == "" {
		return fmt.Errorf("resource amount can not be empty")
	}

	for _, char := range r.Resource {
		if !(char >= 'a' && char <= 'z') {
			return fmt.Errorf("resource %s contains invalid char %v", r.Resource, char)
		}
	}

	for _, char := range r.Action {
		if !(char >= 'a' && char <= 'z') {
			return fmt.Errorf("resource %s action %s contains invalid char %v", r.Resource, r.Action, char)
		}
	}

	amount := r.Amount
	hasUnitSuffix := slices.Contains(RCTL_UNIT_SUFFIXES_LOWER, r.Amount[len(r.Amount)-1])

	if !hasUnitSuffix {
		hasUnitSuffix = slices.Contains(RCTL_UNIT_SUFFIXES_UPPER, r.Amount[len(r.Amount)-1])
	}

	if hasUnitSuffix {
		amount = r.Amount[:len(r.Amount)-1]
	}

	_, err := strconv.Atoi(amount)
	if err != nil {
		return fmt.Errorf("resource %s amount %s must be a number: %v", r.Resource, r.Amount, err)
	}

	return nil
}

func (r *JailResourceManager) Import() error {
	stdout, _, err := RunCmd(&CmdOptions{
		Path: "/usr/bin/rctl",
		Args: []string{"-h"},
	})

	if err != nil {
		return err
	}

	for line := range strings.SplitSeq(string(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		elements := strings.Split(line, ":")
		if len(elements) < 4 {
			return fmt.Errorf("found invalid line in rctl output, that's weird: %s", line)
		}

		if elements[0] != "jail" {
			continue
		}

		jail := elements[1]

		actionEls := strings.Split(elements[3], "=")
		if len(actionEls) != 2 {
			return fmt.Errorf("found invalid action line in rctl output: %s", line)
		}

		// ignoring `per` here because I won't support it
		amountEls := strings.Split(actionEls[1], "/")

		rlimit := ResourceLimit{
			Resource: elements[2],
			Action:   actionEls[0],
			Amount:   amountEls[0],
		}

		rule := rlimit.Rule(jail)

		r.set(jail, rule, rlimit)
	}

	return nil
}

func (r *JailResourceManager) destroy(rule string) error {
	_, stderr, err := RunCmd(&CmdOptions{
		Path: "/usr/bin/rctl",
		Args: []string{"-r", rule},
	})

	if err != nil && !bytes.Contains(stderr, []byte("No such process")) {
		return err
	}

	return nil
}

func (r *JailResourceManager) DestroyAll(jail string) error {
	for rule := range r.Limits[jail] {
		log.Printf("destroying rctl rule %s", rule)
		err := r.destroy(rule)
		if err != nil {
			return err
		}

		delete(r.Limits[jail], rule)
	}

	return nil
}

func (r *JailResourceManager) Add(jail string, limits []ResourceLimit) error {
	toDestroy := []string{}
	toCreate := map[string]*ResourceLimit{}

	for idx := range limits {
		desired := &limits[idx]
		toCreate[desired.Rule(jail)] = desired
	}

	existingLimits, ok := r.Limits[jail]
	if ok {
		for rule := range existingLimits {
			_, alive := toCreate[rule]
			if alive {
				delete(toCreate, rule)
			} else {
				toDestroy = append(toDestroy, rule)
			}
		}
	}

	for _, rule := range toDestroy {
		err := r.destroy(rule)
		if err != nil {
			return err
		}

		delete(r.Limits[jail], rule)
	}

	for _, rlimit := range toCreate {
		rule := rlimit.Rule(jail)

		_, _, err := RunCmd(&CmdOptions{
			Path: "/usr/bin/rctl",
			Args: []string{"-a", rule},
		})

		if err != nil {
			return err
		}

		r.set(jail, rule, *rlimit)
	}

	return nil
}
