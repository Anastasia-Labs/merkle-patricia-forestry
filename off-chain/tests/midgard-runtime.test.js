import test from 'ava';

import { Store } from '../lib/store.js';
import { Branch, Trie } from '../lib/trie.js';

const ITEMS = [
  { key: 'alpha', value: '1' },
  { key: 'bravo', value: '2' },
  { key: 'charlie', value: '3' },
  { key: 'delta', value: '4' },
];

test('hydratePaths authenticates and retains only touched paths', async t => {
  const store = new Store();
  const trie = await Trie.fromList(ITEMS, store);

  t.true(trie instanceof Branch);
  t.false(trie.children.some(child => child instanceof Trie));

  const metrics = await trie.hydratePaths([
    ITEMS[0].key,
    ITEMS[0].key,
    { key: ITEMS[1].key, type: 'delete' },
  ]);

  t.is(metrics.uniquePaths, 2);
  t.true(metrics.loadedNodes > 0);
  t.is((await trie.get(ITEMS[0].key)).toString(), ITEMS[0].value);
  t.true(trie.assertHydratedNodeHashes(64).verifiedNodes > 1);

  const detached = trie.cloneDetached();
  t.not(detached, trie);
  t.true(detached.hash.equals(trie.hash));
  t.false(detached.children.some(child => child instanceof Trie));

  const collapsed = trie.collapseHydratedChildren(0);
  t.true(collapsed.collapsedNodes > 0);
  t.false(trie.children.some(child => child instanceof Trie));
});

test('retained branches update Merkle caches incrementally without root drift', async t => {
  const store = new Store();
  store.retainHydratedChildren = true;

  const trie = await Trie.fromList(ITEMS, store);
  Trie.enableMidgardBranchHashDiagnostics();
  Trie.resetMidgardBranchHashDiagnostics();

  await trie.insert('echo', '5');
  await trie.insert('foxtrot', '6');

  const expected = await Trie.fromList([
    ...ITEMS,
    { key: 'echo', value: '5' },
    { key: 'foxtrot', value: '6' },
  ]);
  const diagnostics = Trie.midgardBranchHashDiagnostics();

  t.true(trie.hash.equals(expected.hash));
  t.true(diagnostics.initializations > 0);
  t.true(diagnostics.incrementalUpdates > 0);
  t.true(trie.assertHydratedNodeHashes(64).verifiedNodes > 1);

  Trie.enableMidgardBranchHashDiagnostics(false);
});
