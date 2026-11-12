import base64
from email.message import Message
import json
import unittest
from unittest.mock import patch

import demo


def token(claims):
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    return 'header.' + payload + '.signature'


class DemoChecks(unittest.TestCase):
    def test_claim_checks_reject_missing_routing_legacy_shape_and_long_lifetime(self):
        claims = {'deployment_id': 'test1234', 'region': 'us-east-1', 'iat': 100, 'exp': 1000}
        self.assertEqual(demo.check_claims(token(claims), 'test1234', 'us-east-1'), 900)
        for changes in [{'deployment_id': 'other'}, {'region': None},
                        {'federation_rule_id': 'legacy'}, {'exp': 1001}, {'exp': 100}]:
            with self.subTest(changes=changes), self.assertRaises(demo.DemoFailure):
                demo.check_claims(token({**claims, **changes}), 'test1234', 'us-east-1')

    def test_routing_requires_all_three_headers(self):
        values = {'x-rawtree-routed-deployment-id': 'test1234',
                  'x-rawtree-routed-region': 'us-east-1', 'x-rawtree-routed-source': 'federation'}
        headers = Message()
        for key, value in values.items():
            headers[key] = value
        demo.check_routing(headers, 'test1234', 'us-east-1')
        for key in values:
            with self.subTest(key=key):
                altered = Message()
                for name, value in values.items():
                    if name != key:
                        altered[name] = value
                with self.assertRaises(demo.DemoFailure):
                    demo.check_routing(altered, 'test1234', 'us-east-1')

    def test_http_failure_does_not_include_response_body(self):
        from urllib.error import HTTPError
        import io
        error = HTTPError('https://example.invalid', 401, 'unauthorized', {}, io.BytesIO(b'secret-token'))
        with patch('demo.build_opener') as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaises(demo.DemoFailure) as raised:
                demo.request('Exchange', 'https://example.invalid')
        self.assertNotIn('secret-token', str(raised.exception))


if __name__ == '__main__':
    unittest.main()
