import importlib.util
from pathlib import Path
from unittest import mock

import testtools


# render-review.py lives in tools/ (outside the importable package) and its
# filename contains a hyphen, so load it as a module by path.
_RENDER_REVIEW_PATH = (
    Path(__file__).resolve().parents[3] / 'tools' / 'render-review.py')
_spec = importlib.util.spec_from_file_location(
    'render_review', _RENDER_REVIEW_PATH)
render_review = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(render_review)


def _valid_review():
    return {
        'summary': 'A short summary of the review.',
        'items': [
            {
                'id': 1,
                'title': 'Something to fix',
                'category': 'bug',
                'action': 'fix',
                'severity': 'high',
                'description': 'A description.',
                'location': 'kerbside/foo.py:10',
                'suggestion': 'Do the thing.',
            },
        ],
    }


class ValidateReviewFallbackTestCase(testtools.TestCase):
    """Exercise the hand-rolled validator used when jsonschema is absent.

    The address-comments automation depends on validate_review() to reject
    malformed review JSON before Claude acts on it, so the fallback path is
    forced on here (HAS_JSONSCHEMA=False) to keep coverage deterministic
    regardless of whether jsonschema happens to be installed.
    """

    def setUp(self):
        super().setUp()
        patch = mock.patch.object(render_review, 'HAS_JSONSCHEMA', False)
        patch.start()
        self.addCleanup(patch.stop)

    def test_valid_document_passes(self):
        is_valid, error = render_review.validate_review(_valid_review())
        self.assertTrue(is_valid)
        self.assertEqual('', error)

    def test_missing_summary_is_rejected(self):
        data = _valid_review()
        del data['summary']
        is_valid, error = render_review.validate_review(data)
        self.assertFalse(is_valid)
        self.assertIn('summary', error)

    def test_missing_items_is_rejected(self):
        data = _valid_review()
        del data['items']
        is_valid, error = render_review.validate_review(data)
        self.assertFalse(is_valid)
        self.assertIn('items', error)

    def test_items_must_be_a_list(self):
        data = _valid_review()
        data['items'] = {'not': 'a list'}
        is_valid, error = render_review.validate_review(data)
        self.assertFalse(is_valid)
        self.assertIn('array', error)

    def test_missing_item_field_is_rejected(self):
        data = _valid_review()
        del data['items'][0]['category']
        is_valid, error = render_review.validate_review(data)
        self.assertFalse(is_valid)
        self.assertIn('category', error)

    def test_invalid_action_is_rejected(self):
        data = _valid_review()
        data['items'][0]['action'] = 'delete-everything'
        is_valid, error = render_review.validate_review(data)
        self.assertFalse(is_valid)
        self.assertIn('action', error)


class RenderMarkdownTestCase(testtools.TestCase):
    def test_smoke_renders_expected_sections(self):
        markdown = render_review.render_markdown(_valid_review())
        self.assertIn('## PR Review', markdown)
        self.assertIn('### Summary', markdown)
        self.assertIn('A short summary of the review.', markdown)
        self.assertIn('### Action Items', markdown)
        self.assertIn('Something to fix', markdown)

    def test_embed_json_appends_machine_readable_block(self):
        markdown = render_review.render_markdown(
            _valid_review(), embed_json=True)
        self.assertIn('Machine-readable review data', markdown)
        self.assertIn('```json', markdown)
