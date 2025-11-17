# Copyright (C) 2015, Som Inc.
# Created by Som, Inc. <info@som.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest

with patch('som.common.som_uid'):
    with patch('som.common.som_gid'):
        from som.core.logtest import send_logtest_msg, validate_dummy_logtest
        from som.core.common import LOGTEST_SOCKET
        from som.core.exception import SomError


@pytest.mark.parametrize('params', [
    {'command': 'random_command', 'parameters': {'param1': 'value1'}},
    {'command': None, 'parameters': None}
])
@patch('som.core.logtest.SomSocketJSON.__init__', return_value=None)
@patch('som.core.logtest.SomSocketJSON.send')
@patch('som.core.logtest.SomSocketJSON.close')
@patch('som.core.logtest.create_som_socket_message')
def test_send_logtest_msg(create_message_mock, close_mock, send_mock, init_mock, params):
    """Test `send_logtest_msg` function from module core.logtest.

    Parameters
    ----------
    params : dict
        Params that will be sent to the logtest socket.
    """
    with patch('som.core.logtest.SomSocketJSON.receive',
               return_value={'data': {'response': True, 'output': {'timestamp': '1970-01-01T00:00:00.000000-0200'}}}):
        response = send_logtest_msg(**params)
        init_mock.assert_called_with(LOGTEST_SOCKET)
        create_message_mock.assert_called_with(origin={'name': 'Logtest', 'module': 'framework'}, **params)
        assert response == {'data': {'response': True, 'output': {'timestamp': '1970-01-01T02:00:00.000000Z'}}}


@patch('som.core.logtest.SomSocketJSON.__init__', return_value=None)
@patch('som.core.logtest.SomSocketJSON.send')
@patch('som.core.logtest.SomSocketJSON.close')
@patch('som.core.logtest.create_som_socket_message')
def test_validate_dummy_logtest(create_message_mock, close_mock, send_mock, init_mock):
    with patch('som.core.logtest.SomSocketJSON.receive',
               return_value={'data': {'codemsg': -1}, 'error': 0}):
        with pytest.raises(SomError) as err_info:
            validate_dummy_logtest()

        assert err_info.value.code == 1113
