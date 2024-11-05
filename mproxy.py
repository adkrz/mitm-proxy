import argparse
import os
import socket
import ssl
import sys
import threading
import subprocess

# Globals
log_dir = None
request_num = 0
openssl_path = r"C:\Program Files\Git\mingw64\bin\openssl.exe"

remove_encoding_headers = True  # sometimes problematic, e.g. TP-Link router login page
buffer_size=8162
client_context_cache = {}
client_context_cache_lock = threading.Lock()
server_context = ssl.create_default_context()


def validate_port(port):
    if port > 65535 or port < 1025:
        print("ERROR: port number out of proper range")
        exit(0)


def parse_input_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='version', version='mproxy version 0.1 by Alok Gupta',
                        help='shows app version info')
    parser.add_argument('-n', '--numworker', nargs='?', type=int, default='100',
                        help='number of workers to be used for concurent requests')
    parser.add_argument('-p', '--port', nargs='?', type=int, help='port to connect to', default=8080)
    parser.add_argument('-t', '--timeout', nargs='?', type=int, default='-1',
                        help='wait time for server response before timing out')
    parser.add_argument('-l', '--log', nargs='?', default=None, const=os.getcwd(),
                        help='logs all requests and responses')
    args = parser.parse_args()

    validate_port(args.port)

    log = None
    if args.log:
        log = str(args.log)
        if not os.path.exists(log):
            print("ERROR: log directory must already exist")
            exit()

    return args.port, args.numworker, args.timeout, log


def proxy_server(webserver, port, conn, data, addr, filename):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((webserver, port))
        s.send(data)
        while 1:
            reply = s.recv(buffer_size)
            if reply:
                conn.send(reply)
            else:
                break


def is_ssl_req(data):
    first_line = data.split(b'\n')[0]
    return first_line.split(b' ')[0] == b'CONNECT'


def replace_with_proper_url(url, webserver):
    if b"http://" in url:
        url = url[7:]

    if webserver in url:
        url = url[len(webserver):]

    return url


def sanitize_headers(data_arr):
    # Remove keep alive connection, replace with close connection
    try:
        conn_keep_alive_ind = data_arr.index(b"Connection: keep-alive\r")
        if conn_keep_alive_ind != -1:
            data_arr[conn_keep_alive_ind] = b"Connection: close\r"
    except ValueError:
        pass

    # Remove encoding
    if remove_encoding_headers:
        accept_enc_index = [idx for idx, s in enumerate(data_arr) if s.startswith(b"Accept-Encoding:")]
        if accept_enc_index:
            data_arr.pop(accept_enc_index[0])


def sanitize_data(data, webserver):
    data_arr = data.split(b'\n')

    # Replace first line with route, not full domain
    first_line = data_arr[0].split(b" ")
    first_line[1] = replace_with_proper_url(first_line[1], webserver)
    first_line_str = b" ".join(first_line)
    data_arr[0] = first_line_str

    sanitize_headers(data_arr)

    data = b"\n".join(data_arr)

    return data


def get_client_ssl_context(domain):
    with client_context_cache_lock:
        if domain in client_context_cache:
            client_context = client_context_cache[domain]
        else:
            client_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            client_context_cache[domain] = client_context
            cert_file = "certs/" + domain + ".pem"

            if not os.path.exists(cert_file):
                ext_file = "certs/" + domain + ".ext"
                with open(ext_file, "wt") as ext:
                    ext.write(f"subjectAltName = DNS:{domain}\n")
                    ext.write(f"authorityKeyIdentifier = keyid,issuer\n")
                    ext.write(f"basicConstraints = CA:FALSE\n")
                    ext.write(f"keyUsage = digitalSignature, keyEncipherment\n")
                    ext.write(f"extendedKeyUsage=serverAuth\n")

                cmd = f"x509 -req -CA root_ca/root-ca.crt -CAkey root_ca/root-ca.key -in root_ca/server.csr "\
                      f"-out {cert_file} -days 365 -CAcreateserial -extfile {ext_file}"
                args = [openssl_path]
                split = cmd.split(" ")
                for c in split:
                    if c:
                        args.append(c)
                subprocess.call(args)
            client_context.load_cert_chain(cert_file, keyfile="root_ca/server.key")
    return client_context


def https_proxy_server(port, conn, data, addr, webserver):
    conn.send(b'HTTP/1.1 200 OK\r\n\r\n')
    domain = webserver.decode("ASCII")

    client_context = get_client_ssl_context(domain)

    try:
        ssl_client_socket = client_context.wrap_socket(conn, server_side=True)
        ssl_res = ssl_client_socket.read(buffer_size)
    except (ssl.SSLEOFError, ConnectionAbortedError, ConnectionResetError):
        return
    except Exception as ex:
        if "SSLV3_ALERT_BAD_CERTIFICATE" in str(ex):
            return
        else:
            raise
    lines = ssl_res.split(b"\n")
    sanitize_headers(lines)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        ssl_server_socket = server_context.wrap_socket(server_socket, server_hostname=webserver)
        ssl_server_socket.connect((webserver, int(port)))

        data = b"\n".join(lines)
        ssl_server_socket.send(data)
        try:
            while 1:
                reply = ssl_server_socket.recv(buffer_size)
                if reply:
                    ssl_client_socket.send(reply)
                else:
                    break
        except ssl.SSLEOFError:
            pass


def parse_req(conn, data, addr):
    # Client Browser requests
    with conn:
        first_line = data.split(b'\n')[0]
        if not first_line:
            return
        url = first_line.split(b' ')[1]
        http_pos = url.find(b"://")

        temp = url if http_pos == -1 else url[(http_pos + 3):]
        port_pos = temp.find(b":")

        webserver_pos = temp.find(b"/")
        if webserver_pos == -1:
            webserver_pos = len(temp)

        is_https_request = is_ssl_req(data)

        if port_pos == -1 or webserver_pos < port_pos:
            port = 80
            webserver = temp[:webserver_pos]
        else:
            port = int(temp[(port_pos + 1):]) if is_https_request else int(
                (temp[(port_pos + 1):])[webserver_pos - port_pos - 1])
            webserver = temp[:port_pos]

        file_name = None

        addr_str = str(addr[0])

        if log_dir:
            file_name = str(log_dir) + str(request_num) + '_' + addr_str + '_' + str(webserver)

        if is_https_request:
            https_proxy_server(port, conn, data, addr, webserver)
        else:
            data = sanitize_data(data, webserver)
            try:
                proxy_server(webserver, port, conn, data, addr, file_name)
            except (ConnectionResetError, ConnectionAbortedError):
                pass


def accept_conn(s):
    global request_num
    while True:
        try:
            conn, addr = s.accept()
            data = conn.recv(buffer_size)
            request_num += 1
            threading.Thread(target=parse_req, args=(conn, data, addr)).start()
        except:
            s.close()
            print("Shutting proxy server")
            sys.exit(1)


def connect_socket(num_workers, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', port))
        s.listen(num_workers)
        print("Initialized and bind to socket - SUCCESS")
    except:
        print("Err with socket init")
        sys.exit(2)

    accept_conn(s)


def main():
    global log_dir
    port, num_workers, timeout, log_dir = parse_input_args()
    if log_dir and not log_dir.endswith('/'):
        log_dir = log_dir + '/'
    connect_socket(num_workers, port)


if __name__ == '__main__':
    main()
