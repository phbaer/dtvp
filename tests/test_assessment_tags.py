import unittest
from logic import process_assessment_details


class TestAssessmentTags(unittest.TestCase):
    def test_assessment_details_basic(self):
        details = "Some details."
        user = "alice"
        role = "USER"

        result, state = process_assessment_details(details, user, role)

        self.assertIn("[Assessed By: alice]", result)
        self.assertIn("Some details.", result)
        self.assertEqual(state, "NOT_SET")

    def test_assessment_details_rescored_max(self):
        # We need to simulate the team blocks or rely on the extraction
        # Since process_assessment_details now parses blocks, we give it a multi-team state
        existing = (
            "--- [Team: Security] [State: EXPLOITABLE] [Assessed By: bob] [Rescored: 4.0] ---\n"
            "Bad.\n"
            "--- [Team: App] [State: NOT_AFFECTED] [Assessed By: charlie] [Rescored: 8.5] ---\n"
            "Fine."
        )
        user = "new_user"
        role = "USER"
        team = "Security"
        new_details = "Updated security analysis.\n[Rescored: 9.0]"  # Team Security updates their score

        result, state = process_assessment_details(
            new_details,
            user,
            role,
            team=team,
            state="EXPLOITABLE",
            existing_details=existing,
        )

        # Global tag at the top should be the max (9.0)
        self.assertTrue(result.startswith("[Rescored: 9.0]"))
        # Per-team scores stay in headers. Security updated from 4.0 to 9.0.
        self.assertIn("[Rescored: 8.5]", result)  # App's score stays
        self.assertIn(
            "[Team: Security] [State: EXPLOITABLE] [Assessed By: new_user] [Rescored: 9.0]",
            result,
        )
        self.assertEqual(state, "EXPLOITABLE")
        # Ensure no extra --- from bad parsing
        self.assertNotIn("---\n---", result)

    def test_assessment_details_state_aggregation_worst(self):
        existing = (
            "--- [Team: Security] [State: NOT_AFFECTED] [Assessed By: bob] ---\n"
            "Looks safe."
        )
        user = "alice"
        role = "USER"
        team = "App"
        new_state = "EXPLOITABLE"
        new_details = "Actually we found it is exploitable here."

        result, state = process_assessment_details(
            new_details,
            user,
            role,
            team=team,
            state=new_state,
            existing_details=existing,
        )

        # Aggregated state should be EXPLOITABLE
        self.assertEqual(state, "EXPLOITABLE")
        self.assertIn("[Team: Security] [State: NOT_AFFECTED]", result)
        self.assertIn("[Team: App] [State: EXPLOITABLE]", result)

    def test_assessment_details_state_aggregation_in_triage(self):
        existing = (
            "--- [Team: Security] [State: NOT_AFFECTED] [Assessed By: bob] ---\n"
            "--- [Team: Dev] [State: RESOLVED] [Assessed By: charlie] ---"
        )
        user = "analyst"
        role = "USER"
        team = "QA"
        new_state = "IN_TRIAGE"

        result, state = process_assessment_details(
            "Checking...",
            user,
            role,
            team=team,
            state=new_state,
            existing_details=existing,
        )

        # IN_TRIAGE (1) is worse than RESOLVED (5) or NOT_AFFECTED (4)
        self.assertEqual(state, "IN_TRIAGE")

    def test_assessment_details_reviewer_updates_preserves_pending(self):
        # With the decoupled approval workflow, updates by reviewers
        # NO LONGER automatically clear the pending status.
        existing = "Details.\n\n[Status: Pending Review]"
        user = "admin"
        role = "REVIEWER"

        result, state = process_assessment_details(
            "Updated details.", user, role, existing_details=existing
        )

        self.assertIn("[Status: Pending Review]", result)
        self.assertIn("[Assessed By: admin]", result)

    def test_assessment_details_analyst_adds_pending(self):
        details = "Draft..."
        user = "analyst1"
        role = "ANALYST"

        result, state = process_assessment_details(details, user, role)

        self.assertIn("[Status: Pending Review]", result)

    def test_assessment_details_legacy_preservation(self):
        existing = "This is some legacy text without team markers."
        user = "alice"
        role = "USER"
        team = "Security"
        state_in = "EXPLOITABLE"

        result, state = process_assessment_details(
            "New team info.",
            user,
            role,
            team=team,
            state=state_in,
            existing_details=existing,
        )

        self.assertIn("This is some legacy text without team markers.", result)
        self.assertIn(
            "--- [Team: Security] [State: EXPLOITABLE] [Assessed By: alice] ---", result
        )

    def test_assessment_details_update_same_team(self):
        existing = "--- [Team: Security] [State: IN_TRIAGE] [Assessed By: bob] ---\nInitial report."
        user = "charlie"
        role = "USER"
        team = "Security"
        state_in = "EXPLOITABLE"

        result, state = process_assessment_details(
            "Found exploit!",
            user,
            role,
            team=team,
            state=state_in,
            existing_details=existing,
        )

        # Should only have ONE Security block, and it should be updated
        self.assertEqual(result.count("--- [Team: Security]"), 1)
        self.assertIn("[State: EXPLOITABLE]", result)
        self.assertIn("[Assessed By: charlie]", result)
        self.assertIn("Found exploit!", result)
        self.assertNotIn("Initial report.", result)


if __name__ == "__main__":
    unittest.main()
