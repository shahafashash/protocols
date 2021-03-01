from challenge_response import CHAPClient

if __name__ == '__main__':
    client = CHAPClient()
    res = client.connect_to_server()
    print(f'[*] Client connection status: {res}')
    client.conn.close()