import unittest
from logic import process_assessment_details


class TestAssessmentTags(unittest.TestCase):
    def test_assessment_details_basic(self):
        details = "Some details."
        user = "alice"
        role = "USER"

        result = process_assessment_details(details, user, role)

        self.assertIn("[Assessed By: alice]", result)
        self.assertIn("Some details.", result)
        self.assertNotIn("[Reviewed By:", result)

    def test_assessment_details_rescored_max(self):
        details = "History:\n[Rescored: 4.0]\n[Rescored: 8.5]\n[Rescored: 6.0]"
        user = "bob"
        role = "USER"

        result = process_assessment_details(details, user, role)

        # Should pick max 8.5
        self.assertIn("[Rescored: 8.5]", result)
        self.assertNotIn("[Rescored: 4.0]", result)
        self.assertNotIn("[Rescored: 6.0]", result)

        # Check count
        self.assertEqual(result.count("[Rescored:"), 1)

    def test_assessment_details_rescored_vector(self):
        details = "[Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]"
        user = "charlie"
        role = "USER"

        result = process_assessment_details(details, user, role)

        self.assertIn(
            "[Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]", result
        )
        self.assertIn("[Assessed By: charlie]", result)

    def test_assessment_details_reviewer(self):
        details = "LGTM"
        user = "dave"
        role = "REVIEWER"

        result = process_assessment_details(details, user, role)

        self.assertIn("[Assessed By: dave]", result)
        self.assertIn("[Reviewed By: dave]", result)

    def test_assessment_details_analyst_pending(self):
        details = "Analysis done."
        user = "eve"
        role = "ANALYST"

        result = process_assessment_details(details, user, role)

        self.assertIn("[Assessed By: eve]", result)
        self.assertIn("[Status: Pending Review]", result)

    def test_assessment_details_analyst_already_pending(self):
        details = "Analysis done.\n[Status: Pending Review]"
        user = "eve"
        role = "ANALYST"

        result = process_assessment_details(details, user, role)

        self.assertIn("[Assessed By: eve]", result)
        # Should not duplicate
        self.assertEqual(result.count("[Status: Pending Review]"), 1)

    def test_assessment_details_update_authorship(self):
        details = "Old details.\n[Assessed By: old_user]\n[Reviewed By: old_reviewer]"
        user = "new_user"
        role = "USER"

        result = process_assessment_details(details, user, role)

        self.assertIn("[Assessed By: new_user]", result)
        self.assertNotIn("old_user", result)
        self.assertNotIn(
            "old_reviewer", result
        )  # Removed since new user is not reviewer
        self.assertIn("Old details.", result)


if __name__ == "__main__":
    unittest.main()
