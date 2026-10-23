"""api-key is a credential header, in either casing."""

import unittest

from prismor.runtime.proxy import without_client_auth


class TestApiKeyHeader(unittest.TestCase):
    def test_api_key_is_stripped(self):
        kept = without_client_auth({
            "Authorization": "Bearer prismor-virtual",
            "api-key": "client-api-key",
            "Api-Key": "client-Api-Key",
            "Content-Type": "application/json",
        })
        self.assertEqual(list(kept), ["Content-Type"])
