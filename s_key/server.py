from skey import SKeyServer

if __name__ == '__main__':
    server = SKeyServer()
    res = server.wait_for_connection()
    print(f'[*] Server connection status: {res}')
    if res == True:
        server.conn.close()
