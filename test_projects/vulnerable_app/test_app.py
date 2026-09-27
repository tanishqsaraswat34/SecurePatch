import unittest
from unittest.mock import patch

import app
import utils
import web


class SecurePatchFunctionalTests(unittest.TestCase):

    def test_get_user(self):
        db = app.create_database()

        result = app.get_user(db, "1")

        self.assertEqual(
            result,
            [(1, "alice")],
        )

    def test_get_user_for_second_user(self):
        db = app.create_database()

        result = app.get_user(db, "2")

        self.assertEqual(
            result,
            [(2, "bob")],
        )

    def test_run_diagnostic(self):
        with patch(
            "utils.subprocess.run"
        ) as mock_run:

            mock_run.return_value.returncode = 0

            result = utils.run_diagnostic(
                "localhost"
            )

            self.assertEqual(
                result.returncode,
                0,
            )

            self.assertTrue(
                mock_run.called
            )

    def test_render_profile(self):
        result = web.render_profile(
            "alice"
        )

        self.assertEqual(
            result,
            "<div class='profile'>alice</div>",
        )


if __name__ == "__main__":
    unittest.main()