import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "app" / "components"))

import api_client


class ApiPostTests(unittest.TestCase):
    @patch("api_client.requests.post")
    def test_post_returns_json_response(self, post):
        response = Mock()
        response.json.return_value = {"report": "Rapport"}
        post.return_value = response

        result, error = api_client.api_post(
            "/api/incidents/INC-1/report",
            timeout=610,
        )

        self.assertEqual(result, {"report": "Rapport"})
        self.assertIsNone(error)
        post.assert_called_once_with(
            f"{api_client.API_BASE_URL}/api/incidents/INC-1/report",
            json=None,
            timeout=610,
        )

    @patch("api_client.requests.post")
    def test_post_returns_api_error_detail(self, post):
        response = Mock()
        response.json.return_value = {"detail": "Ollama indisponible"}
        response.raise_for_status.side_effect = api_client.requests.HTTPError("503")
        post.return_value = response

        result, error = api_client.api_post("/api/incidents/INC-1/report")

        self.assertIsNone(result)
        self.assertIn("Ollama indisponible", error)

    @patch("api_client.requests.post")
    def test_post_reports_connection_error(self, post):
        post.side_effect = api_client.requests.ConnectionError("offline")

        result, error = api_client.api_post("/api/incidents/INC-1/report")

        self.assertIsNone(result)
        self.assertIn("Impossible de contacter l'API", error)


if __name__ == "__main__":
    unittest.main()
