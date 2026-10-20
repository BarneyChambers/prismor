"""Generation paths that used to skip the proxy screen."""

from prismor.runtime.proxy import generation_route, is_passthrough


def test_missed_generation_paths_are_routed():
    cases = {
        "/v1/completions": "openai",
        "/v1/messages/": "anthropic",
        "/v1/%6dessages": "anthropic",
        "/model/x/invoke-with-response-stream": "anthropic",
        "/v1beta/models/gemini-2.5-pro:batchGenerateContent": "google",
        "/v1/chat/completions": "openai",
    }
    for path, provider in cases.items():
        routed = generation_route(path)
        assert routed is not None and routed[1] == provider, path


def test_health_and_embeddings_stay_passthrough():
    for path in ("/health", "/v1/models", "/v1/embeddings"):
        assert is_passthrough(path), path
        assert generation_route(path) is None
    assert not is_passthrough("/v1/not-a-real-route")
    assert generation_route("/v1/not-a-real-route") is None
