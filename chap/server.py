from challenge_response import CHAPServer

if __name__ == '__main__':
    server = CHAPServer()
    res = server.wait_for_connection()
    print(f'[*] Server connection status: {res}')
    server.conn.close()