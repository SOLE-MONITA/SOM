# Copyright (C) 2015, Som Inc.
# Created by Som, Inc. <info@som.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, MagicMock

import pytest

from som.core.exception import SomException
from som.core.som_socket import SomSocket, SomSocketJSON, SOCKET_COMMUNICATION_PROTOCOL_VERSION, \
    create_som_socket_message


@patch('som.core.som_socket.SomSocket._connect')
def test_SomSocket__init__(mock_conn):
    """Tests SomSocket.__init__ function works"""

    SomSocket('test_path')

    mock_conn.assert_called_once_with()


@patch('som.core.som_socket.socket.socket.connect')
def test_SomSocket_protected_connect(mock_conn):
    """Tests SomSocket._connect function works"""

    SomSocket('test_path')

    mock_conn.assert_called_with('test_path')


@patch('som.core.som_socket.socket.socket.connect', side_effect=Exception)
def test_SomSocket_protected_connect_ko(mock_conn):
    """Tests SomSocket._connect function exceptions works"""

    with pytest.raises(SomException, match=".* 1013 .*"):
        SomSocket('test_path')


@patch('som.core.som_socket.socket.socket.connect')
@patch('som.core.som_socket.socket.socket.close')
def test_SomSocket_close(mock_close, mock_conn):
    """Tests SomSocket.close function works"""

    queue = SomSocket('test_path')

    queue.close()

    mock_conn.assert_called_once_with('test_path')
    mock_close.assert_called_once_with()


@patch('som.core.som_socket.socket.socket.connect')
@patch('som.core.som_socket.socket.socket.send')
def test_SomSocket_send(mock_send, mock_conn):
    """Tests SomSocket.send function works"""

    queue = SomSocket('test_path')

    response = queue.send(b"\x00\x01")

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@pytest.mark.parametrize('msg, effect, send_effect, expected_exception', [
    ('text_msg', 'side_effect', None, 1105),
    (b"\x00\x01", 'return_value', 0, 1014),
    (b"\x00\x01", 'side_effect', Exception, 1014)
])
@patch('som.core.som_socket.socket.socket.connect')
def test_SomSocket_send_ko(mock_conn, msg, effect, send_effect, expected_exception):
    """Tests SomSocket.send function exceptions works"""

    queue = SomSocket('test_path')

    if effect == 'return_value':
        with patch('som.core.som_socket.socket.socket.send', return_value=send_effect):
            with pytest.raises(SomException, match=f'.* {expected_exception} .*'):
                queue.send(msg)
    else:
        with patch('som.core.som_socket.socket.socket.send', side_effect=send_effect):
            with pytest.raises(SomException, match=f'.* {expected_exception} .*'):
                queue.send(msg)

    mock_conn.assert_called_once_with('test_path')


@patch('som.core.som_socket.socket.socket.connect')
@patch('som.core.som_socket.unpack', return_value='1024')
@patch('som.core.som_socket.socket.socket.recv')
def test_SomSocket_receive(mock_recv, mock_unpack, mock_conn):
    """Tests SomSocket.receive function works"""

    queue = SomSocket('test_path')

    response = queue.receive()

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@patch('som.core.som_socket.socket.socket.connect')
@patch('som.core.som_socket.socket.socket.recv', side_effect=Exception)
def test_SomSocket_receive_ko(mock_recv, mock_conn):
    """Tests SomSocket.receive function exception works"""

    queue = SomSocket('test_path')

    with pytest.raises(SomException, match=".* 1014 .*"):
        queue.receive()

    mock_conn.assert_called_once_with('test_path')


@patch('som.core.som_socket.SomSocket._connect')
def test_SomSocketJSON__init__(mock_conn):
    """Tests SomSocketJSON.__init__ function works"""

    SomSocketJSON('test_path')

    mock_conn.assert_called_once_with()


@patch('som.core.som_socket.socket.socket.connect')
@patch('som.core.som_socket.SomSocket.send')
def test_SomSocketJSON_send(mock_send, mock_conn):
    """Tests SomSocketJSON.send function works"""

    queue = SomSocketJSON('test_path')

    response = queue.send('test_msg')

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@pytest.mark.parametrize('raw', [
    True, False
])
@patch('som.core.som_socket.socket.socket.connect')
@patch('som.core.som_socket.SomSocket.receive')
@patch('som.core.som_socket.loads', return_value={'error':0, 'message':None, 'data':'Ok'})
def test_SomSocketJSON_receive(mock_loads, mock_receive, mock_conn, raw):
    """Tests SomSocketJSON.receive function works"""
    queue = SomSocketJSON('test_path')
    response = queue.receive(raw=raw)
    if raw:
        assert isinstance(response, dict)
    else:
        assert isinstance(response, str)
    mock_conn.assert_called_once_with('test_path')


@patch('som.core.som_socket.socket.socket.connect')
@patch('som.core.som_socket.SomSocket.receive')
@patch('som.core.som_socket.loads', return_value={'error':10000, 'message':'Error', 'data':'KO'})
def test_SomSocketJSON_receive_ko(mock_loads, mock_receive, mock_conn):
    """Tests SomSocketJSON.receive function works"""

    queue = SomSocketJSON('test_path')

    with pytest.raises(SomException, match=".* 10000 .*"):
        queue.receive()

    mock_conn.assert_called_once_with('test_path')


@pytest.mark.parametrize('origin, command, parameters', [
    ('origin_sample', 'command_sample', {'sample': 'sample'}),
    (None, 'command_sample', {'sample': 'sample'}),
    ('origin_sample', None, {'sample': 'sample'}),
    ('origin_sample', 'command_sample', None),
    (None, None, None)
])
def test_create_som_socket_message(origin, command, parameters):
    """Test create_som_socket_message function."""
    response_message = create_som_socket_message(origin, command, parameters)
    assert response_message['version'] == SOCKET_COMMUNICATION_PROTOCOL_VERSION
    assert response_message.get('origin') == origin
    assert response_message.get('command') == command
    assert response_message.get('parameters') == parameters
