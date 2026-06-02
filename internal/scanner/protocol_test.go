package scanner

import "testing"

func validJob() ScanJob {
	return ScanJob{
		ID:             "job-1",
		AgentID:        "agent-1",
		Type:           ScanHostDiscovery,
		Mode:           ModePassive,
		AllowedCIDRs:   []string{"192.168.10.0/24"},
		Targets:        []string{"192.168.10.20"},
		TimeoutSeconds: 60,
	}
}

func activeAgent() AgentRegistration {
	return AgentRegistration{
		ID:           "agent-1",
		Status:       AgentActive,
		AllowedCIDRs: []string{"192.168.0.0/16"},
	}
}

func TestValidateJobTargetsAllowsContainedCIDRsAndHosts(t *testing.T) {
	job := ScanJob{
		AllowedCIDRs: []string{"192.168.10.0/24"},
		Targets:      []string{"192.168.10.0/25", "192.168.10.20"},
	}
	if err := ValidateJobTargets(job); err != nil {
		t.Fatalf("expected valid targets: %v", err)
	}
}

func TestValidateJobTargetsRejectsOutsideCIDR(t *testing.T) {
	job := ScanJob{
		AllowedCIDRs: []string{"192.168.10.0/24"},
		Targets:      []string{"192.168.11.20"},
	}
	if err := ValidateJobTargets(job); err == nil {
		t.Fatal("expected outside target to be rejected")
	}
}

func TestValidateJobTargetsRejectsIPv6(t *testing.T) {
	job := ScanJob{
		AllowedCIDRs: []string{"192.168.10.0/24"},
		Targets:      []string{"2001:db8::1"},
	}
	if err := ValidateJobTargets(job); err == nil {
		t.Fatal("expected IPv6 target to be rejected")
	}
}

func TestValidateJobRejectsMissingFieldsAndBadEnums(t *testing.T) {
	cases := map[string]func(*ScanJob){
		"missing id":      func(j *ScanJob) { j.ID = "" },
		"missing agent":   func(j *ScanJob) { j.AgentID = "" },
		"bad scan_type":   func(j *ScanJob) { j.Type = "bogus" },
		"bad mode":        func(j *ScanJob) { j.Mode = "bogus" },
		"zero timeout":    func(j *ScanJob) { j.TimeoutSeconds = 0 },
		"target outside":  func(j *ScanJob) { j.Targets = []string{"10.0.0.1"} },
		"no allowed cidr": func(j *ScanJob) { j.AllowedCIDRs = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			job := validJob()
			mutate(&job)
			if err := ValidateJob(job); err == nil {
				t.Fatalf("expected %s to fail validation", name)
			}
		})
	}

	if err := ValidateJob(validJob()); err != nil {
		t.Fatalf("expected valid job to pass: %v", err)
	}
}

func TestValidateJobForAgentEnforcesAgentAllowlist(t *testing.T) {
	if err := ValidateJobForAgent(validJob(), activeAgent()); err != nil {
		t.Fatalf("expected job within agent allowlist to pass: %v", err)
	}

	t.Run("job allowlist outside agent allowlist", func(t *testing.T) {
		job := validJob()
		job.AllowedCIDRs = []string{"10.0.0.0/24"}
		job.Targets = []string{"10.0.0.5"}
		if err := ValidateJobForAgent(job, activeAgent()); err == nil {
			t.Fatal("expected job outside agent allowlist to be rejected")
		}
	})

	t.Run("inactive agent", func(t *testing.T) {
		agent := activeAgent()
		agent.Status = AgentDisabled
		if err := ValidateJobForAgent(validJob(), agent); err == nil {
			t.Fatal("expected disabled agent to be rejected")
		}
	})

	t.Run("agent id mismatch", func(t *testing.T) {
		job := validJob()
		job.AgentID = "other-agent"
		if err := ValidateJobForAgent(job, activeAgent()); err == nil {
			t.Fatal("expected agent_id mismatch to be rejected")
		}
	})
}
