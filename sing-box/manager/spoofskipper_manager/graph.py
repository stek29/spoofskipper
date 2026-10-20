"""One traversal of rendered groups, endpoints and detour dependencies."""
from .identity import sample_key

GROUP_TYPES = ('selector', 'urltest')


class OutboundGraph:
    def __init__(self, config):
        entries = config.get('outbounds', []) + config.get('endpoints', [])
        self.entries = {entry['tag']: entry for entry in entries}
        if len(self.entries) != len(entries):
            raise ValueError('duplicate outbound/endpoint tags')

    def dependencies(self, tag, choices=None, groups_only=False):
        entry = self.entries[tag]
        members = list(entry.get('outbounds', []))
        if entry.get('type') in GROUP_TYPES and choices is not None:
            selected = choices.get(tag, {}).get('now')
            if selected not in members:
                raise ValueError('upstream selection unavailable')
            members = [selected]
        if not groups_only and entry.get('detour'):
            members.append(entry['detour'])
        return members

    def fold(self, tag, combine, *, choices=None, groups_only=False):
        """Reduce a dependency tree, checking missing references and cycles once."""
        done = {}
        def visit(current, ancestors):
            if current in ancestors:
                raise ValueError('outbound dependency cycle')
            if current not in self.entries:
                raise ValueError('unknown outbound dependency')
            if current not in done:
                entry = self.entries[current]
                children = self.dependencies(current, choices, groups_only)
                values = [visit(child, ancestors | {current}) for child in children]
                done[current] = combine(entry, values)
            return done[current]
        return visit(tag, set())

    def validate(self):
        for tag, entry in self.entries.items():
            dependencies = self.dependencies(tag)
            if entry.get('type') in GROUP_TYPES and not dependencies:
                raise ValueError('empty selector group')
            if entry.get('default') and entry['default'] not in dependencies:
                raise ValueError('selector default is not a member')
            self.fold(tag, lambda entry, children: None)

    def leaves(self, tag, groups=None):
        def flatten(entry, children):
            if entry.get('type') in GROUP_TYPES:
                if groups is not None:
                    groups.add(entry['tag'])
                return [leaf for branch in children for leaf in branch]
            return [entry['tag']]
        return self.fold(tag, flatten, groups_only=True)

    def path_identity(self, tag, choices):
        return self.fold(tag, lambda entry, children: (sample_key(entry), tuple(children)), choices=choices)
