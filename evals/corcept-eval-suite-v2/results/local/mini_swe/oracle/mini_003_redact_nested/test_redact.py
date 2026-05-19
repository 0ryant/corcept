from redact import redact

def test_nested_redaction_and_no_mutation():
    original = {'user': {'token': 'abc', 'name': 'ryan'}, 'items': [{'password': 'x'}]}
    out = redact(original)
    assert out['user']['token'] == '<redacted>'
    assert out['items'][0]['password'] == '<redacted>'
    assert original['user']['token'] == 'abc'

def test_case_insensitive_key():
    assert redact({'API_KEY': 'abc'})['API_KEY'] == '<redacted>'
