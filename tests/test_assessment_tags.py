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

    def test_assessment_details_rescored_update(self):
        # The new logic enforces a single block. Updating one team's assessment
        # should replace the entire block with the new assessment.
        existing = (
            "--- [Team: Security] [State: EXPLOITABLE] [Assessed By: bob] [Rescored: 4.0] ---\n"
            "Bad.\n"
        )
        user = "new_user"
        role = "REVIEWER"
        team = "Security"
        new_details = "Updated security analysis.\n[Rescored: 9.0]"

        result, state = process_assessment_details(
            new_details,
            user,
            role,
            team=team,
            state="EXPLOITABLE",
            existing_details=existing,
        )

        # The result should be a single block for Security with the new score.
        self.assertTrue(result.startswith("--- [Team: Security]"))
        self.assertIn("[Rescored: 9.0]", result)
        self.assertIn("Updated security analysis.", result)
        self.assertNotIn("[Rescored: 4.0]", result)
        self.assertEqual(state, "EXPLOITABLE")

    def test_assessment_details_state_aggregation_replacement(self):
        # When a new assessment is provided, it replaces the existing one entirely.
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

        # The result should be the new App assessment. Security assessment is gone.
        self.assertEqual(state, "EXPLOITABLE")
        self.assertNotIn("[Team: Security]", result)
        self.assertIn("[Team: App] [State: EXPLOITABLE]", result)

    def test_assessment_details_reviewer_clears_pending(self):
        # Reviewer updates should clear the [Status: Pending Review] tag.
        # And should preserve the original assessor.
        existing = "Details.\n\n[Status: Pending Review] [Assessed By: bob]"
        user = "admin"
        role = "REVIEWER"

        result, state = process_assessment_details(
            "Updated details.", user, role, existing_details=existing
        )

        self.assertNotIn("[Status: Pending Review]", result)
        self.assertIn("[Assessed By: bob]", result)
        self.assertIn("[Reviewed By: admin]", result)

    def test_assessment_details_analyst_adds_pending(self):
        details = "Draft..."
        user = "analyst1"
        role = "ANALYST"

        result, state = process_assessment_details(details, user, role)

        self.assertIn("[Status: Pending Review]", result)

    def test_assessment_details_legacy_replacement(self):
        # Legacy text is replaced by the new assessment block.
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

        self.assertNotIn("This is some legacy text without team markers.", result)
        self.assertIn(
            "[Team: Security] [State: EXPLOITABLE] [Assessed By: alice]", result
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

        # Should be updated
        self.assertIn("[State: EXPLOITABLE]", result)
        self.assertIn("[Assessed By: charlie]", result)
        self.assertIn("Found exploit!", result)
        self.assertNotIn("Initial report.", result)


if __name__ == "__main__":
    unittest.main()
