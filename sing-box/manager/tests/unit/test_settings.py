"""local-manager.json validation and the immutable settings it produces."""
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from spoofskipper_manager.settings import Settings, load_settings, DEFAULT_PROBE_URLS
from spoofskipper_manager.state import write_json

INVALID = [
    {'probes_enabled': 'yes'},
    {'managed_selectors': ['proxy_main']},  # Ownership requires probes.
    *({'probes_enabled': True, 'managed_selectors': managed}
      for managed in ('proxy_main', [''], ['proxy_main'] * 2, [1], None)),
    *({'selector_priorities': priorities}
      for priorities in ([], {'x': []}, {'x': [['a'], ['a']]}, {'x': ['a']}, {'x': [[1]]})),
    {'provider_weights': {'a': -1}},
    {'revision_timeout': 0},
    {'probe_workers': 5},
    {'probe_port': 19089},  # Same as clash_api_port.
    {'probe_timeout': 16},
    *({'probes_enabled': True, 'probe_urls': urls}
      for urls in ('https://example.test/', [], ['http://example.test/?bytes={bytes}'],
                   ['https://example.test/'] * 2, [1], [['https://example.test/']])),
    *({'probes_enabled': True, 'uplink_urls': urls}
      for urls in ('https://ya.ru/', ['http://ya.ru/'], [{}])),
    *({'dashboard_listen': address} for address in
      ('9090', 'host.lan:9090', '0.0.0.0:0', '[::1:9090', '::1:9090', ':9090', None, '127.0.0.1:19090')),
    {'provider_shortlist_sizes': {'p': -1}}, {'provider_shortlist_sizes': {'p': 1.5}}, {'provider_shortlist_sizes': []},
    {'provider_rotation_seconds': {'p': 0}}, {'provider_rotation_seconds': {'p': True}},
    {'throughput_evidence_mib': 40}, {'throughput_max_mib': 95}, {'shortlist_size': 2.5},
]


class SettingsTests(unittest.TestCase):
    def load(self, data):
        with tempfile.TemporaryDirectory() as temp:
            if data is not None:
                write_json(Path(temp) / 'local-manager.json', data)
            return load_settings(temp)

    def test_invalid_settings_are_rejected(self):
        for data in INVALID:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.load(data)

    def test_missing_file_means_observe_nothing(self):
        settings = self.load(None)
        self.assertFalse(settings.probes_enabled)
        self.assertEqual(settings.managed_selectors, ())

    def test_valid_settings_are_immutable(self):
        settings = self.load({'probes_enabled': True, 'managed_selectors': ['choice'],
                              'provider_weights': {'p': 2},
                              'selector_priorities': {'choice': [['p', 'q'], ['local']]}})
        self.assertEqual(settings.probe_urls, DEFAULT_PROBE_URLS)
        self.assertEqual(settings.selector_priorities['choice'], (('p', 'q'), ('local',)))
        with self.assertRaises(FrozenInstanceError):
            settings.probes_enabled = False
        with self.assertRaises(TypeError):
            settings.provider_weights['p'] = 3
        self.assertEqual(settings.with_changes(managed_selectors=()).managed_selectors, ())
        self.assertEqual(settings.managed_selectors, ('choice',))
        self.assertEqual(self.load({'dashboard_listen': '[::]:9091'}).dashboard_listen, '[::]:9091')
        self.assertIs(Settings.from_mapping(settings), settings)


if __name__ == '__main__':
    unittest.main()
