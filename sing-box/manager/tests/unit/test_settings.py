"""Runtime settings own defaults and cannot be mutated after validation."""
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager.settings import Settings, load_settings, DEFAULT_PROBE_URL
from spoofskipper_manager.state import write_json


class SettingsTests(unittest.TestCase):
    def test_defaults_and_nested_values_are_immutable(self):
        with tempfile.TemporaryDirectory() as temp:
            write_json(Path(temp) / 'local-manager.json', {
                'probes_enabled': True, 'managed_selectors': ['choice'],
                'provider_weights': {'p': 2}, 'selector_priorities': {'choice': [['p']]}})
            settings = load_settings(temp)
        self.assertEqual(settings.probe_url, DEFAULT_PROBE_URL)
        with self.assertRaises(FrozenInstanceError):
            settings.probes_enabled = False
        with self.assertRaises(TypeError):
            settings.provider_weights['p'] = 3
        with self.assertRaises(TypeError):
            settings.selector_priorities['choice'][0][0] = 'other'
        changed = settings.with_changes(managed_selectors=())
        self.assertEqual(settings.managed_selectors, ('choice',))
        self.assertEqual(changed.managed_selectors, ())
        self.assertIs(Settings.from_mapping(settings), settings)
