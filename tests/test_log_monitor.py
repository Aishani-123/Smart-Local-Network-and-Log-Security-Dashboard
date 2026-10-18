import unittest

from monitoring.log_monitor import (
    analyze_log_line,
    failed_login_attempts
)


class TestLogMonitor(unittest.TestCase):

    def setUp(self):
        # Clear previous failed-login attempts before each test
        failed_login_attempts.clear()

    def test_different_users_are_tracked_independently(self):
        # Two failed attempts for admin
        first_admin = analyze_log_line("FAILED_LOGIN user=admin")
        second_admin = analyze_log_line("FAILED_LOGIN user=admin")

        # One failed attempt for guest
        first_guest = analyze_log_line("FAILED_LOGIN user=guest")

        # Neither username should trigger brute-force detection
        self.assertEqual(first_admin["event_type"], "failed_login")
        self.assertEqual(second_admin["event_type"], "failed_login")
        self.assertEqual(first_guest["event_type"], "failed_login")

        # Each username must have an independent attempt count
        self.assertEqual(len(failed_login_attempts["admin"]), 2)
        self.assertEqual(len(failed_login_attempts["guest"]), 1)

    def test_brute_force_detected_for_correct_user(self):
        analyze_log_line("FAILED_LOGIN user=admin")
        analyze_log_line("FAILED_LOGIN user=admin")

        third_attempt = analyze_log_line("FAILED_LOGIN user=admin")

        self.assertEqual(
            third_attempt["event_type"],
            "possible_brute_force"
        )
        self.assertEqual(third_attempt["severity"], "high")


if __name__ == "__main__":
    unittest.main()