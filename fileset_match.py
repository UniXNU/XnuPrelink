#!/usr/bin/env python3
"""Pair functions and data of a stripped fileset kernel with a native kernel that has symbols."""
import argparse
from array import array
from bisect import bisect_right
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from kc_image import Image, scan

EXEC_SEGMENTS = ('__TEXT_EXEC', '__TEXT_BOOT_EXEC', '__KLD', '__LAST')


class Side:
    """Functions, references and pointer fixups of one kernel."""

    def __init__(self, image, fixups, mapped):
        self.image = image
        self.mapped = mapped
        execs = [s for s in image.segments if s['name'] in EXEC_SEGMENTS and s['size']]
        self.exec_ranges = [(s['va'], s['va'] + s['size']) for s in execs]
        backed = [(s['va'], s['va'] + s['filesize']) for s in execs if s['filesize']]
        starts = sorted(a for a in set(image.function_starts()) if self.in_exec(a))
        self.starts = starts
        self.functions, self.callees, self.callers = {}, defaultdict(set), defaultdict(set)
        for index, start in enumerate(starts):
            end = min([e for b, e in self.exec_ranges if b <= start < e] +
                      ([starts[index + 1]] if index + 1 < len(starts) else []))
            for b, e in backed:
                if b <= start < e:
                    end = min(end, e)
            if end - start < 4:
                continue
            calls, refs, shape = scan(image.read(start, end - start), start)
            strings = {}
            for site, address, _ in refs:
                if not self.in_exec(address):
                    text = image.cstring(address)
                    if text is not None and len(text) >= 4:
                        strings[site] = text
            self.functions[start] = {
                'end': end,
                'refs': [(site - start, address) for site, address, _ in refs],
                'length': len(shape),
                'digest': hashlib.md5(array('I', shape)).hexdigest(),
                'strings': strings,
            }
            for _, target, _ in calls:
                if self.in_exec(target):
                    at = bisect_right(starts, target) - 1
                    if at >= 0:
                        self.callees[start].add(starts[at])
                        self.callers[starts[at]].add(start)
        self.symbol_names = image.symbols()
        self.symbol_addrs = sorted(self.symbol_names)
        self.string_owners = defaultdict(set)
        for start, fn in self.functions.items():
            for text in set(fn['strings'].values()):
                self.string_owners[text].add(start)
        self.diversity = defaultdict(set)
        for _, (target, auth, _, diversity, _) in fixups.items():
            if auth and diversity and self.in_mapped(target):
                self.diversity[diversity].add(target)

    def in_exec(self, address):
        return any(b <= address < e for b, e in self.exec_ranges)

    def in_mapped(self, address):
        return any(b <= address < e for b, e in self.mapped)

    def name_at(self, address):
        names, addend = self.symbol_names.get(address), 0
        if not names:
            index = bisect_right(self.symbol_addrs, address) - 1
            if index < 0:
                return None, 0
            base = self.symbol_addrs[index]
            addend = address - base
            if addend > 0x10000:
                return None, 0
            names = self.symbol_names[base]
        return min(names), addend

    def section_of(self, address):
        section = self.image.section(address)
        return f"{section['segment']},{section['name']}" if section else '?'


class Matcher:
    """Bind original functions to native functions; every bind must survive its checks."""

    def __init__(self, original, native):
        self.original, self.native = original, native
        self.pairs, self.reverse, self.how = {}, {}, {}
        self.conflicts = []

    def bind(self, orig, native, how):
        if self.pairs.get(orig) == native:
            return True
        if orig in self.pairs or native in self.reverse:
            self.conflicts.append({'kind': 'double-bind', 'orig': f'{orig:#x}',
                                   'native': f'{native:#x}', 'via': how})
            return False
        self.pairs[orig], self.reverse[native], self.how[orig] = native, orig, how
        return True

    def canon(self, native_start):
        name, _ = self.native.name_at(native_start)
        return name if name else f'{native_start:#x}'

    def anchor_strings(self):
        """Unique string references anchor the first pairs."""
        votes = defaultdict(Counter)
        for text, owners in self.original.string_owners.items():
            targets = self.native.string_owners.get(text)
            if targets and len(owners) == 1 and len(targets) == 1:
                votes[next(iter(owners))][next(iter(targets))] += 1
        claimed = Counter(n for counter in votes.values() for n in counter)
        bound = 0
        for orig, counter in votes.items():
            if len(counter) == 1:
                native = next(iter(counter))
                if claimed[native] == 1:
                    bound += self.bind(orig, native, 'string')
        return bound

    def anchor_shapes(self):
        """A relocation-masked instruction sequence owned by exactly one function per side."""
        groups = defaultdict(lambda: ([], []))
        for orig, fn in self.original.functions.items():
            if orig not in self.pairs:
                groups[(fn['digest'], fn['length'])][0].append(orig)
        for native, fn in self.native.functions.items():
            if native not in self.reverse:
                groups[(fn['digest'], fn['length'])][1].append(native)
        bound = 0
        for originals, natives in groups.values():
            if len(originals) == 1 and len(natives) == 1:
                bound += self.bind(originals[0], natives[0], 'shape')
        return bound


    def propagate(self):
        """Match unmatched functions by their set of already matched neighbor names."""
        index = defaultdict(list)
        for native in self.native.functions:
            if native not in self.reverse:
                names = {self.canon(n) for n in self.native.callees[native] | self.native.callers[native]
                         if n in self.reverse}
                index[frozenset(names)].append(native)
        proposals, claimed = [], Counter()
        for orig in self.original.functions:
            if orig in self.pairs:
                continue
            names = {self.canon(self.pairs[t]) for t in self.original.callees[orig] | self.original.callers[orig]
                     if t in self.pairs}
            candidates = index.get(frozenset(names), [])
            if len(candidates) > 1:
                digest = self.original.functions[orig]['digest']
                candidates = [n for n in candidates if self.native.functions[n]['digest'] == digest]
            if len(candidates) == 1:
                proposals.append((orig, candidates[0]))
                claimed[candidates[0]] += 1
        bound = 0
        for orig, native in proposals:
            if claimed[native] == 1:
                bound += self.bind(orig, native, 'calls')
        return bound

    def validate_calls(self):
        """A bound pair must agree on every call edge whose both ends are bound; unbind otherwise."""
        bad = []
        for orig, native in self.pairs.items():
            broken = any(self.pairs.get(t) not in self.native.callees[native]
                         for t in self.original.callees[orig] if t in self.pairs)
            broken = broken or any(self.reverse.get(n) not in self.original.callees[orig]
                                   for n in self.native.callees[native] if n in self.reverse)
            if broken:
                bad.append(orig)
        for orig in bad:
            self.conflicts.append({'kind': 'call-edge', 'orig': f'{orig:#x}',
                                   'native': f'{self.pairs[orig]:#x}', 'via': self.how[orig]})
            del self.reverse[self.pairs.pop(orig)]
            del self.how[orig]
        return len(bad)

    def validate_diversity(self):
        """A pointer diversity is a name hash: a bound pair must not contradict it."""
        bad = []
        for diversity, originals in self.original.diversity.items():
            natives = self.native.diversity.get(diversity)
            if not natives:
                continue
            for orig in originals:
                native = self.pairs.get(orig)
                if native is not None and native not in natives:
                    bad.append(orig)
        for orig in bad:
            self.conflicts.append({'kind': 'diversity', 'orig': f'{orig:#x}',
                                   'native': f'{self.pairs[orig]:#x}', 'via': self.how[orig]})
            del self.reverse[self.pairs.pop(orig)]
            del self.how[orig]
        return len(bad)

    def pair_data(self, known):
        """Identical functions reference their data at identical instruction offsets."""
        votes = defaultdict(Counter)
        for orig, native in self.pairs.items():
            left, right = self.original.functions[orig], self.native.functions[native]
            if left['digest'] != right['digest'] or len(left['refs']) != len(right['refs']):
                continue
            for (offset, address), (native_offset, native_address) in zip(left['refs'], right['refs']):
                if offset != native_offset:
                    break
                if not self.original.in_exec(address) and not self.native.in_exec(native_address) and \
                        self.original.in_mapped(address) and self.native.in_mapped(native_address):
                    votes[address][native_address] += 1
        split = 0
        for address, counter in votes.items():
            if address in known:
                continue
            if len(counter) == 1:
                known[address] = (next(iter(counter)), 'refs')
            else:
                split += 1
        return split

    def diversity_data(self, known):
        """A diversity held by one target per side names that target; binds functions and data."""
        collisions = 0
        for diversity, originals in self.original.diversity.items():
            natives = self.native.diversity.get(diversity)
            if not natives:
                continue
            if len(originals) != 1 or len(natives) != 1:
                collisions += 1
                continue
            orig, native = next(iter(originals)), next(iter(natives))
            if self.original.in_exec(orig) and self.native.in_exec(native):
                self.bind(orig, native, 'diversity')
            elif orig not in known and not self.original.in_exec(orig) and not self.native.in_exec(native):
                known[orig] = (native, 'diversity')
        return collisions

    def report(self, data):
        functions = {}
        for orig in sorted(self.pairs):
            native = self.pairs[orig]
            name, addend = self.native.name_at(native)
            functions[f'{orig:#x}'] = {'native': f'{native:#x}', 'name': name, 'addend': addend,
                                       'how': self.how[orig]}
        payload = {
            'functions': functions,
            'data': {f'{orig:#x}': {'native': f'{native:#x}', 'name': self.native.name_at(native)[0],
                                    'how': how, 'sections': [self.original.section_of(orig),
                                                             self.native.section_of(native)]}
                     for orig, (native, how) in sorted(data.items())},
            'stats': {
                'functions_original': len(self.original.functions),
                'functions_native': len(self.native.functions),
                'functions_matched': len(self.pairs),
                'functions_by_method': dict(Counter(self.how.values())),
                'data_matched': len(data),
                'data_by_method': dict(Counter(how for _, how in data.values())),
                'conflicts': dict(Counter(c['kind'] for c in self.conflicts)),
            },
            'conflicts': self.conflicts[:100],
        }
        return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kernelcache', help='decompressed MH_FILESET kernelcache')
    parser.add_argument('native', help='native arm64e kernel with symbols')
    parser.add_argument('--entry', default='com.apple.kernel', help='fileset entry to pair')
    parser.add_argument('--out', help='write the pairing as JSON to this path')
    parser.add_argument('--max-rounds', type=int, default=40, help='call graph propagation rounds')
    args = parser.parse_args()

    raw = Path(args.kernelcache).read_bytes()
    cache = Image(raw)
    if args.entry not in cache.entries:
        raise SystemExit(f'No fileset entry {args.entry!r}')
    _, at = cache.entries[args.entry]
    entry = Image(raw, at)
    fixups = cache.fixups()
    original = Side(entry, fixups, entry.mapped())
    print(f'original: {len(original.functions)} functions, {len(original.diversity)} diversities')
    native_image = Image(Path(args.native).read_bytes())
    native = Side(native_image, native_image.fixups(), native_image.mapped())
    print(f'native:   {len(native.functions)} functions, {len(native.diversity)} diversities')

    matcher = Matcher(original, native)
    print(f'string anchors: {matcher.anchor_strings()}')
    for _ in range(args.max_rounds):
        bound = matcher.anchor_shapes() + matcher.propagate()
        if not bound:
            break
    for _ in range(3):
        unbound = matcher.validate_calls()
        if not unbound:
            break
        matcher.anchor_shapes(), matcher.propagate()
    matcher.validate_diversity()

    data = {}
    collisions = matcher.diversity_data(data)
    split = matcher.pair_data(data)
    payload = matcher.report(data)

    kernel = entry.mapped()
    inside = lambda address: any(b <= address < e for b, e in kernel)
    targets = {fix[0] for site, fix in fixups.items() if inside(fix[0]) and not inside(site)}
    named = sum(1 for t in targets if t in matcher.pairs or (t in data and data[t] and
                                                             matcher.native.name_at(data[t][0])[0]))
    payload['stats'].update({'kext_targets': len(targets), 'kext_targets_named': named,
                             'diversity_collisions': collisions, 'data_votes_split': split})
    stats = payload['stats']
    print(f"functions: {stats['functions_matched']}/{stats['functions_original']} "
          f"({', '.join(f'{v} {k}' for k, v in sorted(stats['functions_by_method'].items()))})")
    print(f"data: {stats['data_matched']} ({', '.join(f'{v} {k}' for k, v in sorted(stats['data_by_method'].items())) or 'none'})")
    print(f"kext-facing targets named: {named}/{len(targets)}")
    print(f"conflicts: {stats['conflicts'] or 'none'}")
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=1))
        print(f'wrote {args.out}')


if __name__ == '__main__':
    main()
