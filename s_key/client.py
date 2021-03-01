from skey import SKeyClient

if __name__ == '__main__':
    client = SKeyClient()
    res = client.connect_to_server()
    print(f'[*] Client connection status: {res}')
    if res == True:
        client.conn.close()
