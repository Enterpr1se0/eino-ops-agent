package agent

import (
	"testing"

	"eino-ops-agent/internal/domain"
)

func TestDecodeReviewerJSONAndRejectUnexpectedFields(t *testing.T) {
	var review domain.AIRiskReview
	response := "```json\n{\"risk\":\"critical\",\"recommendation\":\"human_required\",\"confidence\":0.8,\"reasons\":[\"service interruption\"],\"missing_evidence\":[],\"required_controls\":[\"verify rollback\"]}\n```"
	if err := decodeJSONObject(response, &review); err != nil {
		t.Fatal(err)
	}
	if err := validateRiskReview(&review); err != nil {
		t.Fatal(err)
	}
	if review.Risk != domain.RiskCritical || review.Recommendation != "human_required" {
		t.Fatalf("unexpected structured review: %#v", review)
	}
	if err := decodeJSONObject(`{"risk":"change","unexpected":true}`, &review); err == nil {
		t.Fatal("expected an unknown structured field to be rejected")
	}
}

func TestReviewInputMasksEnvironmentValues(t *testing.T) {
	input := domain.CommandReviewInput{Request: domain.ExecRequest{Env: map[string]string{"TOKEN": "secret", "MODE": "prod"}}}
	masked := maskReviewInput(input)
	if masked.Request.Env["TOKEN"] != "[configured]" || masked.Request.Env["MODE"] != "[configured]" {
		t.Fatalf("environment values were exposed to the review agents: %#v", masked.Request.Env)
	}
	if input.Request.Env["TOKEN"] != "secret" {
		t.Fatal("masking mutated the execution request")
	}
}

func TestReviewRiskOrdering(t *testing.T) {
	if reviewRiskRank(domain.RiskReadOnly) >= reviewRiskRank(domain.RiskChange) || reviewRiskRank(domain.RiskChange) >= reviewRiskRank(domain.RiskCritical) {
		t.Fatal("review risk ordering is invalid")
	}
	value := domain.AIRiskReview{Risk: domain.RiskForbidden, Recommendation: "deny", Confidence: 1}
	if err := validateRiskReview(&value); err == nil {
		t.Fatal("review agent must not emit a forbidden deterministic policy decision")
	}
}
