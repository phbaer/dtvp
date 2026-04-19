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

    def test_assessment_details_state_aggregation_preservation(self):
        # Now we preserve existing assessments instead of replacing them.
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

        # The result should include BOTH App and Security.
        self.assertEqual(state, "EXPLOITABLE")
        self.assertIn("[Team: Security] [State: NOT_AFFECTED]", result)
        self.assertIn("[Team: App] [State: EXPLOITABLE]", result)

    def test_assessment_details_reviewer_updates_existing_block(self):
        # Reviewer updates should clear the [Status: Pending Review] tag
        # and preserve the original assessor.
        existing = (
            "--- [Team: App] [State: IN_TRIAGE] [Assessed By: bob] ---\n"
            "Details.\n\n"
            "[Status: Pending Review]"
        )
        user = "admin"
        role = "REVIEWER"
        team = "App"

        result, state = process_assessment_details(
            "Updated details.", user, role, team=team, existing_details=existing
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

    def test_assessment_details_legacy_preservation(self):
        # Legacy text is moved into a General block.
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
        self.assertIn("[Team: General]", result)
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

    def test_assessment_details_metadata_leakage_prevention(self):
        # Existing block has some leaked metadata in the details string.
        existing = (
            "--- [Team: TeamA] [State: IN_TRIAGE] [Assessed By: user1] ---\n"
            "Report for TeamA. [Team: TeamB] [Status: Pending Review]\n\n"
            "--- [Team: TeamB] [State: NOT_AFFECTED] [Assessed By: user2] ---\n"
            "Report for TeamB. [Team: InventoryTeam]"
        )
        user = "reviewer"
        role = "REVIEWER"
        team = "TeamA"

        result, _ = process_assessment_details(
            "New TeamA details.", user, role, team=team, existing_details=existing
        )

        # TeamB's details should now be clean of the leaked [Team: InventoryTeam]
        self.assertIn("Report for TeamB.", result)
        self.assertNotIn("[Team: InventoryTeam]", result)
        self.assertNotIn("[Status: Pending Review]", result)

    def test_assigned_users_round_trip(self):
        """Assigned users should be preserved through parse → process → reconstruct."""
        existing = (
            "--- [Team: Security] [State: IN_TRIAGE] [Assessed By: alice] "
            "[Assigned: jane.doe, john.smith] ---\n"
            "Under investigation."
        )
        result, state = process_assessment_details(
            "Still investigating.",
            "alice",
            "ANALYST",
            team="Security",
            state="IN_TRIAGE",
            existing_details=existing,
        )
        self.assertIn("[Assigned: jane.doe, john.smith]", result)
        self.assertIn("Still investigating.", result)

    def test_assigned_users_update(self):
        """Providing a new assigned list should replace the existing one."""
        existing = (
            "--- [Team: Platform] [State: NOT_SET] [Assessed By: bob] "
            "[Assigned: old.user] ---\n"
        )
        result, _ = process_assessment_details(
            "New details.",
            "bob",
            "ANALYST",
            team="Platform",
            state="IN_TRIAGE",
            existing_details=existing,
            assigned=["new.user1", "new.user2"],
        )
        self.assertIn("[Assigned: new.user1, new.user2]", result)
        self.assertNotIn("old.user", result)

    def test_assigned_users_empty_clears(self):
        """Providing an empty assigned list should remove the tag."""
        existing = (
            "--- [Team: Ops] [State: EXPLOITABLE] [Assessed By: carol] "
            "[Assigned: someone] ---\n"
            "Bad."
        )
        result, _ = process_assessment_details(
            "Still bad.",
            "carol",
            "ANALYST",
            team="Ops",
            state="EXPLOITABLE",
            existing_details=existing,
            assigned=[],
        )
        self.assertNotIn("[Assigned:", result)
        self.assertIn("Still bad.", result)

    def test_assigned_users_none_preserves(self):
        """Not providing assigned (None) should preserve existing assignments."""
        existing = (
            "--- [Team: Dev] [State: IN_TRIAGE] [Assessed By: dan] "
            "[Assigned: keeper] ---\n"
            "Checking."
        )
        result, _ = process_assessment_details(
            "Updated.",
            "dan",
            "ANALYST",
            team="Dev",
            state="IN_TRIAGE",
            existing_details=existing,
            assigned=None,
        )
        self.assertIn("[Assigned: keeper]", result)


if __name__ == "__main__":
    unittest.main()
