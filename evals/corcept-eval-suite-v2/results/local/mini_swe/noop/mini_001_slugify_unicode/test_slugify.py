from slugify import slugify

def test_slugify_normalizes_accents():
    assert slugify('Café déjà vu!') == 'cafe-deja-vu'

def test_slugify_empty_is_untitled():
    assert slugify('!!!') == 'untitled'
