import unittest
import mock

from nd_okta_auth import okta


class OktaTest(unittest.TestCase):

    def setUp(self):
        self.client = okta.Okta('server', 'username', 'password')

    def test_init_blank_inputs(self):
        with self.assertRaises(okta.EmptyInput):
            okta.Okta(server='', username='test', password='test')

        with self.assertRaises(okta.EmptyInput):
            okta.Okta(server=None, username='test', password='test')

    def test_request_good_response(self):
        # Ultimately this is the dict we want to get back
        expected_dict = {'ok': True}

        # Create a fake requests.post() response object mock that returns the
        # expected_dict above when json() is called
        fake_response_object = mock.MagicMock(name='response')
        fake_response_object.json.return_value = expected_dict

        with mock.patch('requests.post') as m:
            m.return_value = fake_response_object
            ret = self.client._request('/test', {'test': True})

        # Validate that the call went out as expected, with the supplied input
        m.assert_called_with(
            headers={'Content-Type': 'application/json',
                     'Accept': 'application/json'},
            json={'test': True},
            url='https://server/api/v1/test')

        # Validate that we got back the expected_dict
        self.assertEquals(ret, expected_dict)

    def test_request_with_full_url(self):
        # Ultimately this is the dict we want to get back
        expected_dict = {'ok': True}

        # Create a fake requests.post() response object mock that returns the
        # expected_dict above when json() is called
        fake_response_object = mock.MagicMock(name='response')
        fake_response_object.json.return_value = expected_dict

        with mock.patch('requests.post') as m:
            m.return_value = fake_response_object
            ret = self.client._request('http://test/test', {'test': True})

        # Validate that the call went out as expected, with the supplied input
        m.assert_called_with(
            headers={'Content-Type': 'application/json',
                     'Accept': 'application/json'},
            json={'test': True},
            url='http://test/test')

        # Validate that we got back the expected_dict
        self.assertEquals(ret, expected_dict)

    def test_request_bad_response(self):

        class TestExc(Exception):
            '''Test Exception'''

        fake_response_object = mock.MagicMock(name='response')
        fake_response_object.raise_for_status.side_effect = TestExc()

        with mock.patch('requests.post') as m:
            m.return_value = fake_response_object
            with self.assertRaises(TestExc):
                self.client._request('/test', {'test': True})

    def test_set_token(self):
        input = {
            u'status': u'SUCCESS',
            u'expiresAt': u'2017-07-21T19:23:44.000Z',
            u'_embedded': {
                u'user': {
                    u'profile': {
                        u'locale': u'en',
                        u'lastName': u'Last',
                        u'login': u'test@test.com',
                        u'firstName': u'First',
                        u'timeZone': u'America/Los_Angeles'
                    },
                    u'id': u'fake_id'
                }
            },
            u'sessionToken': u'fake_token'}

        self.client.set_token(input)
        self.assertEquals(self.client.session_token, 'fake_token')
