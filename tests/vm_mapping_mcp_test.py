"""Read-only mapping and pure queue-label replay checks on an explicit authorized device."""
import argparse
import json
import unittest
from urllib.request import Request, urlopen


class MappingTests(unittest.TestCase):
    endpoint = ''

    def raw(self, name, arguments=None):
        body = json.dumps({'jsonrpc': '2.0', 'id': name, 'method': 'tools/call',
                           'params': {'name': name, 'arguments': arguments or {}}}).encode()
        with urlopen(Request(self.endpoint.rstrip('/') + '/api/mcp', body,
                             {'Content-Type': 'application/json'}), timeout=40) as response:
            return json.load(response)['result']

    def call(self, name, arguments=None):
        result = self.raw(name, arguments)
        self.assertFalse(result.get('isError'), result)
        return result.get('structuredContent') or json.loads(result['content'][0]['text'])

    def test_original_target_and_actual_leaf(self):
        for symbol, executable in [('dispatch_block_create', True),
                                   ('dispatch_queue_get_label', True),
                                   ('_NSConcreteGlobalBlock', False)]:
            with self.subTest(symbol=symbol):
                address = self.call('resolve_symbol', {'symbol': symbol})['address']
                result = self.call('get_memory_mapping', {'address': address})
                self.assertTrue(result['found'])
                self.assertEqual(bool(result['executable']), executable)
                self.assertGreater(len(result['walk']), 0)
                self.assertLessEqual(len(result['walk']), result['maxQueries'])
                self.assertTrue(all(step['queryAddress'] == address for step in result['walk']))
                leaf = result['walk'][-1]
                self.assertFalse(leaf['isSubmap'])
                self.assertEqual(bool(leaf['protection'] & 4), executable)
                self.assertLessEqual(int(leaf['start'], 16), int(address, 16))
                self.assertLess(int(address, 16) - int(leaf['start'], 16), int(leaf['length'], 16))

    def test_holes_and_malformed_addresses_do_not_change_hooks(self):
        before = self.call('list_hooks')
        for address in ['0x0', '0x1']:
            result = self.call('get_memory_mapping', {'address': address})
            self.assertFalse(result['found'])
            self.assertFalse(result['executable'])
        for value in [None, True, 1, '', '1', '0x', '0xg', '0x10000000000000000', '0x1\0bad']:
            with self.subTest(value=value):
                self.assertTrue(self.raw('get_memory_mapping', {'address': value}).get('isError'))
        self.assertEqual(self.call('list_hooks'), before)

    def test_system_function_runs_under_qbdi(self):
        generation = self.call('get_capabilities')['processGeneration']
        result = self.call('trace_function', {'symbol': 'dispatch_queue_get_label', 'args': [0],
                                            'max_insns': 1024, 'max_ms': 5000,
                                            'process_generation': generation})
        self.assertTrue(result['call_ok'])
        self.assertTrue(result['retval_valid'])
        self.assertEqual(result['stop_reason'], 'completed')
        self.assertGreater(result['count'], 0)
        label = self.call('read_memory', {'address': result['retval'], 'size': 128})
        self.assertTrue(bytes.fromhex(label['hex']).split(b'\0')[0])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', required=True)
    MappingTests.endpoint = parser.parse_args().endpoint
    unittest.main(argv=[__file__], verbosity=2)
